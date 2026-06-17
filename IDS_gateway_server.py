import sys
import os
os.environ['KMP_DUPLICATE_LIB_OK'] = 'True'
import socket
import struct
import time
import threading
import torch
import warnings
import pandas as pd

warnings.filterwarnings("ignore")

# 必须将 IDS 文件夹加入 sys.path 以便导入其模块
IDS_DIR = os.path.join(os.path.dirname(__file__), "IDS")
sys.path.append(IDS_DIR)

try:
    from utils import capture_and_save_to_csv
    from utils.data_utils import load_captured_traffic
    from models import IDSConvNet, IDSRNN
except ImportError as e:
    print(f"[错误] 无法导入 IDS 模块，请确保脚本位于 Authentication 目录下。详细信息: {e}")
    sys.exit(1)

# --- 全局状态 ---
# 1 = 高性能 (正常), 2 = 强安全 (检测到攻击)
CURRENT_STRATEGY = 1  
STRATEGY_LOCK = threading.Lock()

# --- 配置项 ---
MODEL_TYPE = 'cnn'
DATASET = 'unsw_nb15'
CAPTURE_DURATION = 5  # 每次抓包持续时间(秒)
PORT = 9999

def ids_monitor_thread():
    """后台独立线程，持续抓包并用深度学习模型进行预测"""
    global CURRENT_STRATEGY
    
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"[IDS 流量感知模块] 使用硬件加速: {device}")
    
    # 构造模型路径
    model_path = os.path.join(IDS_DIR, "models", "save", f"{MODEL_TYPE}_{DATASET}_model.pth")
    if not os.path.exists(model_path):
        print(f"[IDS 警告] 模型文件未找到: {model_path}")
        print("您可能需要先在 IDS 目录下运行训练脚本，例如: python main.py --task train --dataset unsw_nb15 --model cnn")
        print("警告: 暂时使用默认高性能策略。")
        # 返回，但不中断服务器，此时只会一直下发策略 1
        return
        
    print(f"[IDS] 成功定位模型: {model_path}。等待首次流量捕获以自动初始化特征矩阵...")
    
    # 模型将在知道真实的 feature_dim 后懒加载初始化
    model = None
    
    while True:
        try:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            # 存放到 dataset 目录便于统筹
            temp_csv = os.path.join(IDS_DIR, "dataset", f"temp_capture_{timestamp}.csv")
            
            print(f"\n[IDS] ========= 开始捕获宿主机流量 {CAPTURE_DURATION} 秒 =========")
            captured_file = capture_and_save_to_csv(
                duration=CAPTURE_DURATION,
                output_path=temp_csv,
                debug=False
            )
            
            if not captured_file or not os.path.exists(captured_file):
                print("[IDS] 无有效流量产出（网络空闲），维持当前安全策略...")
                time.sleep(1)
                continue
                
            # 使用现成的特征预处理管道 (会自行完成标准化处理)
            try:
                X, preprocessor = load_captured_traffic(captured_file)
            except Exception as e:
                print(f"[IDS 数据集错误] 预处理报错 (通常是流量包结构不完整): {e}")
                if os.path.exists(captured_file):
                    os.remove(captured_file)
                continue
                
            if X is None or len(X) == 0:
                print("[IDS] 暂无需要防御的网络流量记录...")
                if os.path.exists(captured_file):
                    os.remove(captured_file)
                continue
                
            feature_dim = X.shape[1]
            
            # 模型单例初始化
            if model is None:
                if MODEL_TYPE == 'cnn':
                    model = IDSConvNet(input_dim=feature_dim)
                elif MODEL_TYPE == 'rnn':
                    # 使用与训练相同的隐藏层维度。如果不匹配请相应修改
                    model = IDSRNN(input_dim=feature_dim, hidden_dim=128, num_layers=2)
                    
                model.load_state_dict(torch.load(model_path, map_location=device))
                model = model.to(device)
                model.eval()
                print(f"[IDS] 深度学习模型就绪！特征维度要求: {feature_dim}")
            
            # 使用模型进行推理
            X_tensor = torch.FloatTensor(X).to(device)
            with torch.no_grad():
                outputs = model(X_tensor)
                _, predicted = torch.max(outputs, 1)
            
            predictions = predicted.cpu().numpy()
            
            # 提取具体的原始网络流信息用于监控输出
            try:
                raw_df = pd.read_csv(captured_file)
                anomaly_indices = [i for i, p in enumerate(predictions) if p == 1]
                if anomaly_indices:
                    print("    [*] 获取到异常流量的具体通信信息 (摘录前5条):")
                    for idx in anomaly_indices[:5]:
                        src_ip = raw_df.iloc[idx].get('Src_ip', 'Unknown')
                        dst_ip = raw_df.iloc[idx].get('Dst_ip', 'Unknown')
                        flow_dur = raw_df.iloc[idx].get('Flow Duration', 0)
                        fwd_pkts = raw_df.iloc[idx].get('Total Fwd Packets', 0)
                        print(f"        -> 嫌疑连接: 源 [{src_ip}] 定向目标 [{dst_ip}] | 持续: {flow_dur:.0f}ms | 包量: {fwd_pkts}")
            except Exception as e:
                pass

            # 根据预测结果调整当前策略
            total_count = len(predictions)
            attack_count = sum(predictions == 1)
            attack_ratio = attack_count / total_count if total_count > 0 else 0
            
            with STRATEGY_LOCK:
                # 规则 1: 如果5秒内捕获的流量极少（<10条流），我们将其判定为“物联网心跳/睡眠资源受限环境”
                if total_count < 10:
                    print(f"[IDS 环境监测] => 流量稀少处于闲置微弱状态，报文流总数: {total_count}")
                    print("[IDS 自动响应] => 降频节能，指示终端算法切换至: [资源受限模式] (策略ID: 3)")
                    CURRENT_STRATEGY = 3
                # 规则 2: 只有当异常报文占比超过 15% 时，才认定为真的受到了网络攻击（容忍真实环境中的误报）
                elif attack_ratio > 0.15:
                    print(f"[IDS 威胁情报] => 发现高频异常报文! 危险比例: ({attack_count}/{total_count} = {attack_ratio:.1%})")
                    print("[IDS 自动响应] => 指示终端算法切换至: [强安全模式] (策略ID: 2)")
                    CURRENT_STRATEGY = 2
                # 规则 3: 流量正常且攻击占比极低，采用最高性能模式
                else:
                    print(f"[IDS 环境监测] => 流量充足且健康，异常比例极低: ({attack_count}/{total_count} = {attack_ratio:.1%})")
                    print("[IDS 自动响应] => 允许终端使用: [高性能模式] (策略ID: 1)")
                    CURRENT_STRATEGY = 1
            
            # 删除临时文件以免塞满硬盘
            if os.path.exists(captured_file):
                os.remove(captured_file)
                
        except Exception as e:
            print(f"[IDS 运行时异常]: {e}")
            time.sleep(2)

def start_server():
    HOST = '127.0.0.1'
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # 允许端口复用
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # 绑定并监听
        s.bind((HOST, PORT))
        s.listen()
        print(f"\n[中央分发大脑] TCP 监听服务已激活 -> {HOST}:{PORT}")
        
        while True:
            conn, addr = s.accept()
            
            def client_handler(connection, address):
                print(f"[TCP] => C++ 终端设备接入成功: {address}")
                with connection:
                    while True:
                        try:
                            # 接收 1 Byte 的心跳请求
                            data = connection.recv(1)
                            if not data:
                                print(f"[TCP] 终端离线: {address}")
                                break
                            
                            # 下发当前最新的 IDS 决策策略
                            with STRATEGY_LOCK:
                                strategy = CURRENT_STRATEGY
                            connection.sendall(struct.pack('i', strategy))
                            
                        except ConnectionResetError:
                            print(f"[TCP] 远端强制终止了连接: {address}")
                            break
                        except Exception as e:
                            print(f"[TCP 服务错误]: {e}")
                            break
                            
            # 开启独立线程处理 C++ 客户端，不阻塞新的连接接入
            threading.Thread(target=client_handler, args=(conn, addr), daemon=True).start()

if __name__ == '__main__':
    # 1. 启动机器学习 IDS 检测线程
    monitor_thread = threading.Thread(target=ids_monitor_thread, daemon=True)
    monitor_thread.start()
    
    # 2. 在主线程运行 Socket 监听
    start_server()
