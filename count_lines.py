import os
from collections import defaultdict

dir_counts = defaultdict(int)

ignore_dirs = {'.git', '__pycache__', 'venv', 'env', '.venv', 'node_modules', '.idea', '.vscode', 'data', 'IDS_data', 'models'}
allowed_exts = {'.py', '.cpp', '.hpp', '.h', '.c', '.js', '.html', '.css', '.json', '.txt', '.md', '.sh', '.bat'}

for root, dirs, files in os.walk(r'd:\code\Authentication'):
    dirs[:] = [d for d in dirs if d not in ignore_dirs]
    for file in files:
        ext = os.path.splitext(file)[1].lower()
        if ext in allowed_exts:
            path = os.path.join(root, file)
            # Skip very large files
            if os.path.getsize(path) > 10 * 1024 * 1024:
                continue
            
            top_level_dir = 'Root'
            rel_path = os.path.relpath(root, r'd:\code\Authentication')
            if rel_path != '.':
                top_level_dir = rel_path.split(os.sep)[0]
                
            try:
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = sum(1 for line in f if line.strip())
                    dir_counts[top_level_dir] += lines
            except Exception as e:
                pass

for top_dir, count in sorted(dir_counts.items(), key=lambda x: x[1], reverse=True):
    print(f'{top_dir}: {count} lines')
