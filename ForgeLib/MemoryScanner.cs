using System;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;

namespace ForgeLib
{
    public class MemoryScanner
    {
        private readonly IntPtr _processHandle;

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenThread(int dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern int NtQueryInformationThread(IntPtr ThreadHandle, int ThreadInformationClass, out THREAD_BASIC_INFORMATION ThreadInformation, int ThreadInformationLength, IntPtr ReturnLength);

        [StructLayout(LayoutKind.Sequential)]
        public struct THREAD_BASIC_INFORMATION
        {
            public IntPtr ExitStatus;
            public IntPtr TebBaseAddress;
            public IntPtr ClientId_UniqueProcess;
            public IntPtr ClientId_UniqueThread;
            public IntPtr AffinityMask;
            public int Priority;
            public int BasePriority;
        }

        public MemoryScanner(int processId)
        {
            Process process = Process.GetProcessById(processId);
            if (process == null)
                throw new ArgumentException("[ERROR] Process not found!");

            _processHandle = OpenProcess(0x1F0FFF, false, process.Id);
            if (_processHandle == IntPtr.Zero)
                throw new Exception("[ERROR] Failed to open process!");
        }

        /// <summary>
        /// Reads memory from the target process.
        /// </summary>
        public bool ReadMemory(IntPtr address, byte[] buffer)
        {
            return ReadProcessMemory(_processHandle, address, buffer, buffer.Length, out _);
        }

        /// <summary>
        /// Scans the process module for the AOB pattern and returns the found address.
        /// </summary>
        public IntPtr FindPattern(string moduleName, byte?[] pattern)
        {
            Process process = Process.GetProcessesByName("MCC-Win64-Shipping")[0];

            ProcessModule module = process.Modules.Cast<ProcessModule>()
                .FirstOrDefault(m => m.ModuleName.Equals(moduleName, StringComparison.OrdinalIgnoreCase));

            if (module == null)
            {
                Console.WriteLine($"[ERROR] Module {moduleName} not found!");
                return IntPtr.Zero;
            }

            IntPtr moduleBase = module.BaseAddress;
            int moduleSize = module.ModuleMemorySize;
            byte[] buffer = new byte[moduleSize];

            Console.WriteLine($"[DEBUG] Scanning {moduleName} - Base: 0x{moduleBase.ToInt64():X}, Size: {moduleSize}");

            if (!ReadProcessMemory(_processHandle, moduleBase, buffer, buffer.Length, out _))
            {
                Console.WriteLine($"[ERROR] Failed to read {moduleName} memory!");
                return IntPtr.Zero;
            }

            return ScanForAOB(buffer, moduleBase, pattern);
        }

        /// <summary>
        /// Scans a memory buffer for an AOB pattern.
        /// </summary>
        private IntPtr ScanForAOB(byte[] buffer, IntPtr baseAddress, byte?[] pattern)
        {
            for (int i = 0; i <= buffer.Length - pattern.Length; i++)
            {
                bool found = true;
                for (int j = 0; j < pattern.Length; j++)
                {
                    if (pattern[j] != null && buffer[i + j] != pattern[j])
                    {
                        found = false;
                        break;
                    }
                }

                if (found)
                {
                    IntPtr foundAddress = baseAddress + i;
                    Console.WriteLine($"[SUCCESS] Found AOB at 0x{foundAddress.ToInt64():X}");
                    return foundAddress;
                }
            }

            Console.WriteLine("[ERROR] AOB not found.");
            return IntPtr.Zero;
        }
    }
}
