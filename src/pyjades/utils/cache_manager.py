import os

def ensure_cache_dir(cache_dir):
    if not os.path.exists(cache_dir):
        os.makedirs(cache_dir)

def clear_cache(cache_dir):
    if os.path.exists(cache_dir):
        for file in os.listdir(cache_dir):
            file_path = os.path.join(cache_dir, file)
            if os.path.isfile(file_path):
                os.remove(file_path)
