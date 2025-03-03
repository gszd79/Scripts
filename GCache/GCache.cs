using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Text.Json;
using System.Runtime.InteropServices;
using System.Management;
using Serilog;

namespace GCache
{
    // Constants
    public static class Constants
    {
        public const string CONFIG_FILE = "cache_config.json";
        public const string LOG_FILE = "cache_manager.log";
        public static readonly HashSet<string> TARGET_EXTENSIONS = new HashSet<string> { ".exe", ".dll", ".sys", ".iso" };
        public const double DEFAULT_CACHE_PERCENT = 0.5;
        public const long MIN_CACHE_GB = 10;
        public const long MAX_CACHE_GB = 500;
    }

    // Logging setup with Serilog
    public static class Logger
    {
        static Logger()
        {
            Log.Logger = new LoggerConfiguration()
                .MinimumLevel.Information()
                .WriteTo.File(Constants.LOG_FILE, outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss} - {Level:u3} - {Message}{NewLine}")
                .CreateLogger();
        }

        public static void Info(string message) => Log.Information(message);
        public static void Warning(string message) => Log.Warning(message);
        public static void Error(string message) => Log.Error(message);
        public static void Critical(string message) => Log.Fatal(message);
    }

    public class RAMCache
    {
        private readonly Dictionary<string, byte[]> cache;
        private readonly LinkedList<string> lruOrder; // To maintain LRU order
        private long maxSize;

        public RAMCache()
        {
            cache = new Dictionary<string, byte[]>();
            lruOrder = new LinkedList<string>();
            maxSize = GetAvailableRAM();
        }

        private long GetAvailableRAM()
        {
            var memInfo = new MEMORYSTATUSEX();
            memInfo.dwLength = (uint)Marshal.SizeOf(typeof(MEMORYSTATUSEX));
            GlobalMemoryStatusEx(ref memInfo);
            return (long)(memInfo.ullAvailPhys * 0.9);
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MEMORYSTATUSEX
        {
            public uint dwLength;
            public uint dwMemoryLoad;
            public ulong ullTotalPhys;
            public ulong ullAvailPhys;
            public ulong ullTotalPageFile;
            public ulong ullAvailPageFile;
            public ulong ullTotalVirtual;
            public ulong ullAvailVirtual;
            public ulong ullAvailExtendedVirtual;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX lpBuffer);

        public void UpdateMaxSize()
        {
            maxSize = GetAvailableRAM();
            TrimCache();
        }

        private void TrimCache()
        {
            long currentSize = cache.Values.Sum(data => (long)data.Length);
            while (currentSize > maxSize && cache.Count > 0)
            {
                var oldest = lruOrder.First.Value;
                lruOrder.RemoveFirst();
                cache.Remove(oldest);
                currentSize = cache.Values.Sum(data => (long)data.Length);
            }
        }

        public bool Add(string path, byte[] data)
        {
            UpdateMaxSize();
            if (data.Length > maxSize) return false;
            TrimCache();
            if (cache.ContainsKey(path))
            {
                lruOrder.Remove(path);
            }
            cache[path] = data;
            lruOrder.AddLast(path);
            return true;
        }

        public byte[] Get(string path)
        {
            if (cache.TryGetValue(path, out byte[] data))
            {
                lruOrder.Remove(path);
                lruOrder.AddLast(path); // Move to end (recently used)
                return data;
            }
            return null;
        }

        public void Remove(string path)
        {
            if (cache.Remove(path))
            {
                lruOrder.Remove(path);
            }
        }
    }

    public class AutoCacheManager
    {
        private readonly double cachePercent;
        private readonly long minCacheBytes;
        private readonly long maxCacheBytes;
        private bool running = true;
        private List<string> hdds = new List<string>();
        private List<string> ssds = new List<string>();
        private string cacheDir;
        private string hddDir;
        private string ssdPath;
        private long cacheSizeBytes;
        private Dictionary<string, string> cachedFiles = new Dictionary<string, string>();
        private readonly RAMCache ramCache;

        public AutoCacheManager(double cachePercent = Constants.DEFAULT_CACHE_PERCENT, 
                              long minGb = Constants.MIN_CACHE_GB, 
                              long maxGb = Constants.MAX_CACHE_GB)
        {
            this.cachePercent = cachePercent;
            this.minCacheBytes = minGb * (1024L * 1024 * 1024);
            this.maxCacheBytes = maxGb * (1024L * 1024 * 1024);
            DetectDrives();
            Directory.CreateDirectory(cacheDir);
            SetInitialCacheSize();
            LoadCache();
            ramCache = new RAMCache();
            Logger.Info($"Initialized with dynamic cache size: {cacheSizeBytes / (1024.0 * 1024 * 1024):F2} GB");
        }

        private void DetectDrives()
        {
            foreach (var drive in DriveInfo.GetDrives())
            {
                if (!drive.IsReady) continue;
                string driveName = drive.Name;
                try
                {
                    var searcher = new ManagementObjectSearcher(
                        $"SELECT * FROM Win32_DiskDrive WHERE DeviceID = '{driveName.Replace("\\", "\\\\")}'");
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        string mediaType = obj["MediaType"]?.ToString() ?? "";
                        if (mediaType.Contains("SSD")) ssds.Add(driveName);
                        else hdds.Add(driveName);
                    }
                }
                catch (Exception e)
                {
                    Logger.Warning($"Could not determine type for {driveName}: {e.Message}");
                }
            }

            if (!ssds.Any() || !hdds.Any()) throw new Exception("No SSD or HDD detected!");
            ssdPath = ssds[0];
            cacheDir = Path.Combine(ssds[0], "Cache");
            hddDir = hdds[0];
            Logger.Info($"SSD cache dir: {cacheDir}, HDD dir: {hddDir}");
        }

        private void SetInitialCacheSize()
        {
            var driveInfo = new DriveInfo(ssdPath);
            long freeSpaceBytes = driveInfo.AvailableFreeSpace;
            long proposedSize = (long)(freeSpaceBytes * cachePercent);
            cacheSizeBytes = Math.Max(minCacheBytes, Math.Min(maxCacheBytes, proposedSize));
        }

        private void AdjustCacheSize()
        {
            var driveInfo = new DriveInfo(ssdPath);
            long freeSpaceBytes = driveInfo.AvailableFreeSpace;
            long totalSpace = driveInfo.TotalSize;
            long newSize = freeSpaceBytes < totalSpace * 0.1 
                ? (long)(freeSpaceBytes * 0.8) 
                : (long)(freeSpaceBytes * cachePercent);
            newSize = Math.Max(minCacheBytes, Math.Min(maxCacheBytes, newSize));
            if (Math.Abs(newSize - cacheSizeBytes) > 1024L * 1024 * 1024)
            {
                cacheSizeBytes = newSize;
                CleanCache();
            }
        }

        private void LoadCache()
        {
            if (File.Exists(Constants.CONFIG_FILE))
            {
                try
                {
                    string json = File.ReadAllText(Constants.CONFIG_FILE);
                    cachedFiles = JsonSerializer.Deserialize<Dictionary<string, string>>(json);
                }
                catch (Exception e)
                {
                    Logger.Error($"Failed to load cache config: {e.Message}");
                }
            }
        }

        private void SaveCache()
        {
            try
            {
                string json = JsonSerializer.Serialize(cachedFiles);
                File.WriteAllText(Constants.CONFIG_FILE, json);
            }
            catch (Exception e)
            {
                Logger.Error($"Failed to save cache config: {e.Message}");
            }
        }

        private long GetCacheSize()
        {
            try
            {
                return Directory.EnumerateFiles(cacheDir, "*", SearchOption.AllDirectories)
                    .Sum(file => new FileInfo(file).Length);
            }
            catch (Exception e)
            {
                Logger.Error($"Error calculating cache size: {e.Message}");
                return 0;
            }
        }

        private bool HasSpace(long fileSize)
        {
            var driveInfo = new DriveInfo(ssdPath);
            long minFree = driveInfo.TotalSize / 20; // 5%
            return (driveInfo.AvailableFreeSpace - fileSize > minFree) && 
                   (GetCacheSize() + fileSize <= cacheSizeBytes);
        }

        public void CacheFile(string filePath)
        {
            string fileStr = filePath;
            byte[] ramData = ramCache.Get(fileStr);
            if (ramData != null)
            {
                Logger.Info($"File served from RAM cache: {filePath}");
                return;
            }

            if (cachedFiles.TryGetValue(fileStr, out string cacheDest))
            {
                byte[] data = File.ReadAllBytes(cacheDest);
                if (ramCache.Add(fileStr, data))
                    Logger.Info($"Loaded to RAM cache: {filePath}");
                return;
            }

            string destPath = Path.Combine(cacheDir, Path.GetRelativePath(hddDir, filePath));
            long fileSize = new FileInfo(filePath).Length;
            AdjustCacheSize();
            if (!HasSpace(fileSize))
            {
                CleanCache();
                if (!HasSpace(fileSize)) return;
            }

            try
            {
                byte[] data = File.ReadAllBytes(filePath);
                if (ramCache.Add(fileStr, data))
                    Logger.Info($"Cached to RAM: {filePath}");
                Directory.CreateDirectory(Path.GetDirectoryName(destPath));
                File.Copy(filePath, destPath, true);
                File.Delete(filePath);
                try
                {
                    File.CreateSymbolicLink(filePath, destPath);
                }
                catch (IOException e)
                {
                    Logger.Warning($"Symbolic link creation failed for {filePath}: {e.Message}. Falling back to copy.");
                    File.Copy(destPath, filePath, true);
                }
                cachedFiles[fileStr] = destPath;
                SaveCache();
                Logger.Info($"Cached to SSD: {filePath}");
            }
            catch (Exception e)
            {
                Logger.Error($"Failed to cache {filePath}: {e.Message}");
                if (File.Exists(destPath)) File.Move(destPath, filePath);
            }
        }

        private void CleanCache()
        {
            ramCache.TrimCache();
            long currentSize = GetCacheSize();
            while (currentSize > cacheSizeBytes && cachedFiles.Any())
            {
                try
                {
                    var oldestFile = cachedFiles.OrderBy(kvp => File.GetLastAccessTime(kvp.Key)).First();
                    File.Delete(oldestFile.Key);
                    File.Move(oldestFile.Value, oldestFile.Key);
                    cachedFiles.Remove(oldestFile.Key);
                    SaveCache();
                    currentSize = GetCacheSize();
                }
                catch (Exception e)
                {
                    Logger.Error($"Error cleaning cache: {e.Message}");
                    cachedFiles.Remove(cachedFiles.Keys.First());
                }
            }
        }

        private void MonitorSystem()
        {
            while (running)
            {
                AdjustCacheSize();
                ramCache.UpdateMaxSize();
                Thread.Sleep(60000); // 60 seconds
            }
        }

        public void Run()
        {
            Logger.Info("GCache started");
            var monitorThread = new Thread(MonitorSystem);
            monitorThread.Start();

            foreach (var file in Directory.EnumerateFiles(hddDir, "*.*", SearchOption.AllDirectories))
            {
                if (!running) break;
                if (Constants.TARGET_EXTENSIONS.Contains(Path.GetExtension(file).ToLower()))
                    CacheFile(file);
            }
            CleanCache();
            Logger.Info("Initial cache run completed");

            while (running)
            {
                Thread.Sleep(10000); // 10 seconds
            }
        }

        public void Stop() => running = false;
    }

    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                var cacheManager = new AutoCacheManager();
                cacheManager.Run();
            }
            catch (Exception e)
            {
                Logger.Critical($"GCache failed: {e.Message}");
                while (true) Thread.Sleep(10000);
            }
        }
    }
}