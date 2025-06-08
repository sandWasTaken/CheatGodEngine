// Enhanced main.cpp with ImGui GUI, WinMain, error handling, and future-ready layout

#include <Windows.h>
#include <d3d11.h>
#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"
#include <TlHelp32.h>
#include <vector>
#include <string>
#include <algorithm>
#define _CRT_SECURE_NO_WARNINGS
#include <psapi.h>
#include <chrono>
#pragma comment(lib, "psapi.lib")

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "d3dcompiler.lib")
#pragma comment(lib, "dxgi.lib")

extern LRESULT ImGui_ImplWin32_WndProcHandler(HWND, UINT, WPARAM, LPARAM);
LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);

// DirectX Globals
ID3D11Device* g_pd3dDevice = nullptr;
ID3D11DeviceContext* g_pd3dDeviceContext = nullptr;
IDXGISwapChain* g_pSwapChain = nullptr;
ID3D11RenderTargetView* g_mainRenderTargetView = nullptr;

void CreateRenderTarget() {
    ID3D11Texture2D* pBackBuffer;
    g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
    g_pd3dDevice->CreateRenderTargetView(pBackBuffer, nullptr, &g_mainRenderTargetView);
    pBackBuffer->Release();
}

void CleanupRenderTarget() {
    if (g_mainRenderTargetView) {
        g_mainRenderTargetView->Release();
        g_mainRenderTargetView = nullptr;
    }
}

bool CreateDeviceD3D(HWND hWnd) {
    DXGI_SWAP_CHAIN_DESC sd = {};
    sd.BufferCount = 2;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hWnd;
    sd.SampleDesc.Count = 1;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    UINT createDeviceFlags = 0;
    const D3D_FEATURE_LEVEL featureLevelArray[1] = { D3D_FEATURE_LEVEL_11_0 };
    D3D_FEATURE_LEVEL featureLevel;

    HRESULT hr = D3D11CreateDeviceAndSwapChain(
        nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, createDeviceFlags,
        featureLevelArray, 1, D3D11_SDK_VERSION, &sd, &g_pSwapChain,
        &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext
    );

    if (FAILED(hr))
        return false;

    CreateRenderTarget();
    return true;
}

void CleanupDeviceD3D() {
    CleanupRenderTarget();
    if (g_pSwapChain) { g_pSwapChain->Release();           g_pSwapChain = nullptr; }
    if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release();    g_pd3dDeviceContext = nullptr; }
    if (g_pd3dDevice) { g_pd3dDevice->Release();           g_pd3dDevice = nullptr; }
}

// -- Settings State --
struct Settings {
    bool alwaysOnTop = true;
    bool darkMode = true;
    bool autoAttach = false;
    bool showFPS = false;
} settings;

void DrawSettingsPanel(HWND hwnd) {
    ImGui::Text("Settings");

    if (ImGui::Checkbox("Always On Top", &settings.alwaysOnTop)) {
        SetWindowPos(hwnd,
            settings.alwaysOnTop ? HWND_TOPMOST : HWND_NOTOPMOST,
            0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
    }

    if (ImGui::Checkbox("Dark Mode", &settings.darkMode)) {
        settings.darkMode ? ImGui::StyleColorsDark() : ImGui::StyleColorsLight();
    }

    ImGui::Checkbox("Auto-Attach on Launch", &settings.autoAttach);
    ImGui::Checkbox("Show FPS", &settings.showFPS);
}


// ------------------------------
// Process Listing + Selection
// ------------------------------

DWORD targetPID = 0;
std::string selectedProcessName = "";

struct ProcEntry {
    std::string name;
    DWORD pid;
    SIZE_T memoryUsage; // ← NEW
};

std::vector<ProcEntry> processList;
int selectedIndex = -1;
bool processListScanned = false;

void RefreshProcessList() {
    processList.clear();

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(snap, &pe32)) {
        do {
            SIZE_T memUsage = 0;
            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);

            if (hProc) {
                PROCESS_MEMORY_COUNTERS pmc;
                if (GetProcessMemoryInfo(hProc, &pmc, sizeof(pmc))) {
                    memUsage = pmc.WorkingSetSize; // in bytes
                }
                CloseHandle(hProc);
            }

            char name[MAX_PATH];
            size_t outSize;
            wcstombs_s(&outSize, name, MAX_PATH, pe32.szExeFile, _TRUNCATE);

            processList.push_back({ name, pe32.th32ProcessID, memUsage });
        } while (Process32Next(snap, &pe32));
    }

    CloseHandle(snap);

    std::sort(processList.begin(), processList.end(), [](const ProcEntry& a, const ProcEntry& b) {
        return a.memoryUsage > b.memoryUsage; // Biggest RAM user first
        });

    processListScanned = true;
}

void DrawProcessSelectorUI() {
    static char processFilter[256] = "";
    static std::vector<std::string> displayNames;

    ImGui::InputTextWithHint("##Filter", "Search processes...", processFilter, IM_ARRAYSIZE(processFilter));
    ImGui::Separator();

    if (processList.empty()) {
        ImGui::Text("No processes found.");
        return;
    }

    displayNames.clear();
    std::vector<const char*> namePtrs;

    for (auto& p : processList) {
        if (strlen(processFilter) > 0) {
            std::string lowercaseName = p.name;
            std::string lowercaseFilter = processFilter;

            std::transform(lowercaseName.begin(), lowercaseName.end(), lowercaseName.begin(), ::tolower);
            std::transform(lowercaseFilter.begin(), lowercaseFilter.end(), lowercaseFilter.begin(), ::tolower);

            if (lowercaseName.find(lowercaseFilter) == std::string::npos)
                continue; // skip if not a match
        }

        std::string label = p.name + " (" + std::to_string(p.pid) + ") - " +
            std::to_string(p.memoryUsage / 1024) + " KB";
        displayNames.push_back(label);
        namePtrs.push_back(displayNames.back().c_str());
    }

    ImGui::Text("Select a process:");
    if (ImGui::ListBox("##ProcessList", &selectedIndex, namePtrs.data(), static_cast<int>(namePtrs.size()), 10)) {
        if (selectedIndex >= 0 && selectedIndex < processList.size()) {
            selectedProcessName = processList[selectedIndex].name;
            targetPID = processList[selectedIndex].pid;
        }
    }

    if (targetPID != 0) {
        ImGui::Text("Selected: %s (PID: %lu)", selectedProcessName.c_str(), targetPID);
    }
}




int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int) {
    WNDCLASSEX wc = { sizeof(WNDCLASSEX), CS_CLASSDC, WndProc, 0, 0,
                      hInstance, nullptr, nullptr, nullptr, nullptr,
                      L"CheatToolWndClass", nullptr };
    RegisterClassEx(&wc);

    HWND hwnd = CreateWindowW(wc.lpszClassName, L"CheatTool GUI",
        WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 1000, 600,
        nullptr, nullptr, wc.hInstance, nullptr);

    SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);

    if (!CreateDeviceD3D(hwnd)) {
        CleanupDeviceD3D();
        UnregisterClassW(wc.lpszClassName, wc.hInstance);
        return 1;
    }

    static auto lastRefresh = std::chrono::steady_clock::now();
    static const std::chrono::seconds refreshInterval(1);

    ShowWindow(hwnd, SW_SHOWDEFAULT);
    UpdateWindow(hwnd);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;

    ImGui::StyleColorsDark();
    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

    MSG msg = {};
    static int currentTab = 0;

    while (msg.message != WM_QUIT) {
        if (PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
            continue;
        }

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        ImGui::Begin("CheatTool Panel", nullptr, ImGuiWindowFlags_MenuBar);

        if (ImGui::BeginMenuBar()) {
            if (ImGui::BeginMenu("Tabs")) {
                if (ImGui::MenuItem("Main"))     currentTab = 0;
                if (ImGui::MenuItem("Settings")) currentTab = 1;
                ImGui::EndMenu();
            }
            ImGui::EndMenuBar();
        }

        auto now = std::chrono::steady_clock::now();
        if (now - lastRefresh >= refreshInterval) {
            RefreshProcessList();
            lastRefresh = now;
        }

        if (currentTab == 0) {
            ImGui::Text("Welcome, Collin. Time to melt some memory.");

            auto now = std::chrono::steady_clock::now();
            if (now - lastRefresh >= refreshInterval) {
                RefreshProcessList();
                lastRefresh = now;
            }

            

            DrawProcessSelectorUI();

            if (ImGui::Button("Attach to Process") && targetPID != 0) {
                // TODO: memory attach
            }
        }

        if (currentTab == 1) {
            DrawSettingsPanel(hwnd);
        }

        if (settings.showFPS) {
            ImGui::SetCursorPosY(ImGui::GetWindowHeight() - 20);
            ImGui::Text("FPS: %.1f", ImGui::GetIO().Framerate);
        }

        ImGui::End();

        ImGui::Render();
        const float clear_color_with_alpha[4] = { 0.1f, 0.1f, 0.1f, 1.0f };
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clear_color_with_alpha);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        g_pSwapChain->Present(1, 0);
    }

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    CleanupDeviceD3D();
    DestroyWindow(hwnd);
    UnregisterClassW(wc.lpszClassName, wc.hInstance);

    return 0;
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;

    switch (msg) {
    case WM_SIZE:
        if (g_pd3dDevice && wParam != SIZE_MINIMIZED) {
            CleanupRenderTarget();
            g_pSwapChain->ResizeBuffers(0, LOWORD(lParam), HIWORD(lParam), DXGI_FORMAT_UNKNOWN, 0);
            CreateRenderTarget();
        }
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hWnd, msg, wParam, lParam);
}
