#include <Windows.h>
#include <mfapi.h>
#include <mfidl.h>
#include <mfobjects.h>
#include <mfreadwrite.h>
#include <mferror.h>
#include <wmcodecdsp.h>
#include <wrl.h> // For ComPtr
#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <locale>
#include <codecvt>

#pragma comment(lib, "mf.lib")
#pragma comment(lib, "mfplat.lib")
#pragma comment(lib, "mfuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "mfreadwrite.lib")

using namespace Microsoft::WRL;

IMFSinkWriter* sinkWriter = nullptr;
DWORD videoStreamIndex;

// Function to initialize Media Foundation for recording
bool InitializeMediaFoundation(const std::wstring& outputFilePath, UINT32 width, UINT32 height) {
    HRESULT hr = MFStartup(MF_VERSION);
    if (FAILED(hr)) {
        std::cerr << "Failed to initialize Media Foundation" << std::endl;
        return false;
    }

    hr = MFCreateSinkWriterFromURL(outputFilePath.c_str(), nullptr, nullptr, &sinkWriter);
    if (FAILED(hr)) {
        std::cerr << "Failed to create sink writer" << std::endl;
        return false;
    }

    ComPtr<IMFMediaType> mediaType;
    hr = MFCreateMediaType(&mediaType);
    if (FAILED(hr)) return false;

    mediaType->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video);
    mediaType->SetGUID(MF_MT_SUBTYPE, MFVideoFormat_H264);
    mediaType->SetUINT32(MF_MT_AVG_BITRATE, 5000000); // 5 Mbps
    mediaType->SetUINT32(MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive);
    MFSetAttributeSize(mediaType.Get(), MF_MT_FRAME_SIZE, width, height);
    MFSetAttributeRatio(mediaType.Get(), MF_MT_FRAME_RATE, 30, 1);
    MFSetAttributeRatio(mediaType.Get(), MF_MT_PIXEL_ASPECT_RATIO, 1, 1);

    hr = sinkWriter->AddStream(mediaType.Get(), &videoStreamIndex);
    if (FAILED(hr)) return false;

    ComPtr<IMFMediaType> inputType;
    hr = MFCreateMediaType(&inputType);
    if (FAILED(hr)) return false;

    inputType->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video);
    inputType->SetGUID(MF_MT_SUBTYPE, MFVideoFormat_RGB32);
    MFSetAttributeSize(inputType.Get(), MF_MT_FRAME_SIZE, width, height);
    MFSetAttributeRatio(inputType.Get(), MF_MT_FRAME_RATE, 30, 1);
    MFSetAttributeRatio(inputType.Get(), MF_MT_PIXEL_ASPECT_RATIO, 1, 1);

    hr = sinkWriter->SetInputMediaType(videoStreamIndex, inputType.Get(), nullptr);
    if (FAILED(hr)) return false;

    hr = sinkWriter->BeginWriting();
    return SUCCEEDED(hr);
}

// Function to finalize Media Foundation recording
void FinalizeMediaFoundation() {
    if (sinkWriter) {
        sinkWriter->Finalize();
        sinkWriter->Release();
        sinkWriter = nullptr;
    }
    MFShutdown();
}

// Function to check if the active window is a fullscreen application
bool IsFullscreenWindow(HWND hwnd) {
    RECT windowRect, desktopRect;
    GetWindowRect(hwnd, &windowRect);

    HWND desktop = GetDesktopWindow();
    GetWindowRect(desktop, &desktopRect);

    return (windowRect.left == desktopRect.left && windowRect.top == desktopRect.top &&
        windowRect.right == desktopRect.right && windowRect.bottom == desktopRect.bottom);
}

int main() {
    std::wstring outputFilePath = L"C:\\Users\\User\\Videos\\output.mp4";
    UINT32 width = 1920, height = 1080;

    if (!InitializeMediaFoundation(outputFilePath, width, height)) {
        return -1;
    }

    std::cout << "Recording started. Monitoring fullscreen application..." << std::endl;

    HWND activeWindow;
    bool isFullscreen = false;

    while (true) {
        activeWindow = GetForegroundWindow();
        if (IsFullscreenWindow(activeWindow)) {
            if (!isFullscreen) {
                std::cout << "Fullscreen app detected." << std::endl;
                isFullscreen = true;
            }
        }
        else {
            if (isFullscreen) {
                std::cout << "Exited fullscreen app. Stopping recording..." << std::endl;
                break;
            }
        }

        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    FinalizeMediaFoundation();

    // Convert and display output path
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    std::cout << "Recording stopped. Saved to " << converter.to_bytes(outputFilePath) << std::endl;

    return 0;
}
