import winreg
import win32api
import win32security
import win32con
import os
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import ctypes
import shutil
import datetime

LOG_PATH = r"C:\\Windows\\INF\\setupapi.dev.log"
LOG_OUTPUT_FILE = os.path.join(os.getcwd(), "usb_cleaner_log.txt")


# Проверка запуска от имени администратора
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


# Получение владельца ключа
def take_ownership(full_path):
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, full_path, 0, winreg.KEY_ALL_ACCESS)
        sd = win32security.GetSecurityInfo(
            key,
            win32security.SE_REGISTRY_KEY,
            win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION
        )

        admin_sid = win32security.LookupAccountName(None, os.getlogin())[0]
        win32security.SetSecurityInfo(
            key,
            win32security.SE_REGISTRY_KEY,
            win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION,
            admin_sid, admin_sid, None, None
        )
        return True
    except Exception:
        return False


# Рекурсивное удаление ключей
def delete_key_recursive(root, path):
    try:
        open_key = winreg.OpenKey(root, path, 0, winreg.KEY_ALL_ACCESS)
        info = winreg.QueryInfoKey(open_key)
        for i in range(info[0] - 1, -1, -1):
            subkey = winreg.EnumKey(open_key, i)
            delete_key_recursive(root, f"{path}\\{subkey}")
        winreg.DeleteKey(open_key, "")
        return True
    except Exception:
        return False


# Получение всех USB ID из реестра
def get_connected_usb_ids():
    usb_ids = []
    try:
        root_path = r"SYSTEM\\CurrentControlSet\\Enum\\USB"
        usb_root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, root_path)
        for i in range(winreg.QueryInfoKey(usb_root)[0]):
            device_class = winreg.EnumKey(usb_root, i)
            class_key = winreg.OpenKey(usb_root, device_class)
            for j in range(winreg.QueryInfoKey(class_key)[0]):
                device_id = winreg.EnumKey(class_key, j)
                usb_ids.append(device_id)
    except Exception:
        pass
    return sorted(set(usb_ids))


# Поиск и удаление ключей, содержащих серийный номер
def search_and_destroy_registry(sn, log_callback, progress_callback):
    root_path = r"SYSTEM\\CurrentControlSet\\Enum\\USB"
    paths_to_check = []

    try:
        usb_root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, root_path)
        for i in range(0, winreg.QueryInfoKey(usb_root)[0]):
            device_class = winreg.EnumKey(usb_root, i)
            class_key = winreg.OpenKey(usb_root, device_class)
            for j in range(0, winreg.QueryInfoKey(class_key)[0]):
                device_id = winreg.EnumKey(class_key, j)
                if sn.lower() in device_id.lower():
                    full_path = f"{root_path}\\{device_class}\\{device_id}"
                    paths_to_check.append(full_path)
    except Exception as e:
        log_callback(f"[ОШИБКА] Поиск в реестре: {str(e)}")
        return

    total = len(paths_to_check)
    for idx, path in enumerate(paths_to_check):
        progress_callback(idx + 1, total)
        log_callback(f"[ИНФО] Найдено в реестре: {path}")
        if not take_ownership(path):
            log_callback(f"[ОШИБКА] Не удалось получить права на: {path}")
            continue
        if delete_key_recursive(winreg.HKEY_LOCAL_MACHINE, path):
            log_callback(f"[УСПЕХ] Удалено: {path}")
        else:
            log_callback(f"[ОШИБКА] Не удалось удалить: {path}")


# Удаление из setupapi.dev.log
def clean_setupapi_log(sn, log_callback):
    backup = LOG_PATH + ".bak"
    try:
        shutil.copyfile(LOG_PATH, backup)
        with open(LOG_PATH, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        blocks = []
        current_block = []
        match_found = False

        for line in lines:
            current_block.append(line)
            if line.strip() == "":
                block_text = "".join(current_block)
                if sn.lower() in block_text.lower():
                    match_found = True
                else:
                    blocks.append(current_block.copy())
                current_block = []

        with open(LOG_PATH, "w", encoding="utf-8") as f:
            for block in blocks:
                f.writelines(block)

        if match_found:
            log_callback(f"[УСПЕХ] Блоки с {sn} удалены из setupapi.dev.log")
        else:
            log_callback(f"[ИНФО] В setupapi.dev.log ID не найден")
    except Exception as e:
        log_callback(f"[ОШИБКА] setupapi.dev.log: {str(e)}")


# GUI
class CleanerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("USB Cleaner Tool")
        self.root.geometry("720x600")
        self.root.resizable(False, False)
        self.sn_var = tk.StringVar()
        self.log_lines = []

        style = ttk.Style()
        style.configure("TButton", font=("Segoe UI", 10))
        style.configure("TLabel", font=("Segoe UI", 10))

        tk.Label(root, text="Выберите ID/серийный номер устройства:").pack(pady=10)
        self.combo = ttk.Combobox(root, textvariable=self.sn_var, font=("Consolas", 11), width=50)
        self.combo['values'] = get_connected_usb_ids()
        self.combo.pack(pady=5)

        self.progress = ttk.Progressbar(root, length=600, mode="determinate")
        self.progress.pack(pady=10)

        self.log_box = tk.Text(root, height=20, width=95, bg="#1e1e1e", fg="#00ff00", insertbackground="white")
        self.log_box.pack(padx=10, pady=5)

        btn_frame = tk.Frame(root)
        btn_frame.pack(pady=10)

        ttk.Button(btn_frame, text="Удалить", width=20, command=self.start_cleaning).grid(row=0, column=0, padx=5)
        ttk.Button(btn_frame, text="Сохранить лог", width=20, command=self.save_log).grid(row=0, column=1, padx=5)
        ttk.Button(btn_frame, text="Выход", width=20, command=root.quit).grid(row=0, column=2, padx=5)

    def log(self, text):
        timestamp = datetime.datetime.now().strftime("[%H:%M:%S]")
        line = f"{timestamp} {text}"
        self.log_lines.append(line)
        self.log_box.insert(tk.END, line + "\n")
        self.log_box.see(tk.END)
        self.root.update_idletasks()

    def update_progress(self, value, max_val):
        self.progress["maximum"] = max_val
        self.progress["value"] = value
        self.root.update_idletasks()

    def start_cleaning(self):
        sn = self.sn_var.get().strip()
        if not sn:
            messagebox.showwarning("Ошибка", "Выберите ID устройства.")
            return
        self.log_lines.clear()
        self.log(f"[ИНФО] Начинаем удаление ID: {sn}")
        search_and_destroy_registry(sn, self.log, self.update_progress)
        clean_setupapi_log(sn, self.log)
        self.log("[ГОТОВО] Очистка завершена!")

    def save_log(self):
        try:
            with open(LOG_OUTPUT_FILE, "w", encoding="utf-8") as f:
                f.write("\n".join(self.log_lines))
            messagebox.showinfo("Сохранено", f"Лог сохранён в {LOG_OUTPUT_FILE}")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось сохранить лог: {e}")


if __name__ == "__main__":
    if not is_admin():
        messagebox.showerror("Ошибка", "Запустите программу от имени администратора.")
        exit(1)
    root = tk.Tk()
    app = CleanerApp(root)
    root.mainloop()
