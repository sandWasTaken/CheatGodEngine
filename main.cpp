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
    SIZE_T memoryUsage;
    std::string arch;
    std::string fullPath;     // NEW
    DWORD threadCount;        // NEW
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
            char name[MAX_PATH];
            size_t outSize;
            wcstombs_s(&outSize, name, MAX_PATH, pe32.szExeFile, _TRUNCATE);

            std::string nameLower = name;
            std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::tolower);

            bool isKernel = (
                nameLower == "wininit.exe" ||
                nameLower == "csrss.exe" ||
                nameLower == "services.exe" ||
                nameLower == "lsass.exe"
                );

            bool isPseudo = (
                nameLower == "system" ||
                nameLower == "registry" ||
                nameLower == "memory compression" ||
                nameLower.find("svchost") != std::string::npos ||
                nameLower.find("idle") != std::string::npos ||
                nameLower.find("smss") != std::string::npos ||
                nameLower.find("system process") != std::string::npos
                );

            SIZE_T memUsage = 0;
            std::string architecture = "??";
            std::string fullPath = "";
            DWORD threadCount = pe32.cntThreads;

            HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
            if (hProc) {
                PROCESS_MEMORY_COUNTERS pmc;
                if (GetProcessMemoryInfo(hProc, &pmc, sizeof(pmc))) {
                    memUsage = pmc.WorkingSetSize;
                }

                TCHAR pathBuf[MAX_PATH];
                if (GetModuleFileNameEx(hProc, NULL, pathBuf, MAX_PATH)) {
                    char pathChar[MAX_PATH];
                    wcstombs_s(&outSize, pathChar, MAX_PATH, pathBuf, _TRUNCATE);
                    fullPath = pathChar;
                }

                BOOL isWow64 = FALSE;
                if (IsWow64Process(hProc, &isWow64)) {
#ifdef _WIN64
                    architecture = isWow64 ? "x86" : "x64";
#else
                    architecture = "x86";
#endif
                }

                CloseHandle(hProc);
            }

            if (isKernel) architecture = "K";
            else if (isPseudo) architecture = "P";

            processList.push_back({ name, pe32.th32ProcessID, memUsage, architecture, fullPath, threadCount });

        } while (Process32Next(snap, &pe32));
    }

    CloseHandle(snap);

    std::sort(processList.begin(), processList.end(), [](const ProcEntry& a, const ProcEntry& b) {
        if (a.arch == "K" || a.arch == "P") return false;
        if (b.arch == "K" || b.arch == "P") return true;
        return a.memoryUsage > b.memoryUsage; // default sort by memory
        });

    processListScanned = true;
}




void DrawProcessSelectorUI() {
    static char processFilter[256] = "";
    static std::vector<int> filteredIndexMap;
    static int selectedRow = -1;
    static bool sortByMemory = true;

    // Top: Sort toggle + search input + reset
    ImGui::Checkbox("Sort by memory", &sortByMemory);
    ImGui::SameLine();
    ImGui::Text("Welcome, Collin. Time to melt some memory.");

    ImGui::InputTextWithHint("##Filter", "Search processes...", processFilter, IM_ARRAYSIZE(processFilter));
    ImGui::SameLine();
    if (ImGui::Button("X")) processFilter[0] = '\0';

    ImGui::Separator();

    // Sort based on user toggle
    std::sort(processList.begin(), processList.end(), [&](const ProcEntry& a, const ProcEntry& b) {
        if (a.arch == "K" || a.arch == "P") return false;
        if (b.arch == "K" || b.arch == "P") return true;

        return sortByMemory
            ? a.memoryUsage > b.memoryUsage
            : a.name < b.name;
        });

    float footerHeight = ImGui::GetFrameHeightWithSpacing() * 2.5f;
    float availableHeight = ImGui::GetContentRegionAvail().y - footerHeight;

    ImGui::BeginChild("ScrollableTable", ImVec2(0, availableHeight), true);

    filteredIndexMap.clear();

    if (ImGui::BeginTable("ProcessTable", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable)) {
        ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed);
        ImGui::TableSetupColumn("Arch", ImGuiTableColumnFlags_WidthFixed);
        ImGui::TableSetupColumn("Threads", ImGuiTableColumnFlags_WidthFixed);
        ImGui::TableHeadersRow();

        for (int i = 0; i < processList.size(); ++i) {
            const ProcEntry& p = processList[i];

            if (strlen(processFilter) > 0) {
                std::string nameLower = p.name;
                std::string filterLower = processFilter;
                std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::tolower);
                std::transform(filterLower.begin(), filterLower.end(), filterLower.begin(), ::tolower);

                if (nameLower.find(filterLower) == std::string::npos)
                    continue;
            }

            filteredIndexMap.push_back(i);
            ImGui::TableNextRow();

            // Name column
            ImGui::TableSetColumnIndex(0);
            std::string label = p.name + "##" + std::to_string(p.pid);
            bool isSelected = (selectedRow == filteredIndexMap.size() - 1);
            if (ImGui::Selectable(label.c_str(), isSelected, ImGuiSelectableFlags_SpanAllColumns)) {
                selectedRow = filteredIndexMap.size() - 1;
                selectedIndex = i;
                selectedProcessName = p.name;
                targetPID = p.pid;
            }
            if (ImGui::IsItemHovered()) {
                ImGui::SetTooltip("%s", p.fullPath.c_str());
            }
            if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0)) {
                // Attach-to-process trigger
                // TODO: Insert actual attach code
            }

            // Size column
            ImGui::TableSetColumnIndex(1);
            ImGui::Text("%zu MB", p.memoryUsage / (1024 * 1024));

            // Arch column
            ImGui::TableSetColumnIndex(2);
            ImVec4 color = ImVec4(1, 1, 1, 1);
            if (p.arch == "x64") color = ImVec4(0.4f, 1.0f, 0.4f, 1.0f);
            else if (p.arch == "x86") color = ImVec4(1.0f, 1.0f, 0.4f, 1.0f);
            else if (p.arch == "K" || p.arch == "P") color = ImVec4(0.9f, 0.5f, 0.5f, 1.0f);
            ImGui::TextColored(color, "%s", p.arch.c_str());

            // Thread count column
            ImGui::TableSetColumnIndex(3);
            ImGui::Text("%lu", p.threadCount);
        }

        ImGui::EndTable();
    }

    ImGui::EndChild();

    if (targetPID != 0) {
        ImGui::Separator();
        ImGui::Text("Selected: %s (PID: %lu)", selectedProcessName.c_str(), targetPID);
        if (ImGui::Button("Attach to Process", ImVec2(-1, 0))) {
            // TODO: process attach logic
        }
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

        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(ImGui::GetIO().DisplaySize);
        ImGui::Begin("CheatTool Panel", nullptr, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar);

        if (ImGui::BeginTabBar("Tabs", ImGuiTabBarFlags_Reorderable)) {
            if (ImGui::BeginTabItem("Main")) {
                currentTab = 0;
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Settings")) {
                currentTab = 1;
                ImGui::EndTabItem();
            }
            ImGui::EndTabBar();
        }


        auto now = std::chrono::steady_clock::now();
        if (now - lastRefresh >= refreshInterval) {
            RefreshProcessList();
            lastRefresh = now;
        }

        if (currentTab == 0) {
            
            auto now = std::chrono::steady_clock::now();
            if (now - lastRefresh >= refreshInterval) {
                RefreshProcessList();
                lastRefresh = now;
            }

            

            DrawProcessSelectorUI();

            
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
