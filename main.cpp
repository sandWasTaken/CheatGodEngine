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
    SIZE_T memoryUsage = 0;
    DWORD threadCount = 0;              // 👈 Add this line
    bool is64bit = false;
    bool isElevated = false;
    uintptr_t entryPoint = 0;
    uintptr_t imageBase = 0;
    std::string architecture = "Unknown";
    std::string engine = "Unknown";
    std::string protection = "None";
    std::string fullPath = "";
    std::string subsystem = "Unknown";
    std::chrono::system_clock::time_point startTime;
    std::vector<std::string> modules;
    std::vector<std::string> suspiciousThreads;
};


std::vector<ProcEntry> processList;
int selectedIndex = -1;
bool processListScanned = false;

void RefreshProcessList() {
    processList.clear();
    
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(snapshot, &pe)) {
        CloseHandle(snapshot);
        return;
    }

    do {
        ProcEntry entry;
        entry.threadCount = pe.cntThreads;
        char exeName[MAX_PATH];
        wcstombs_s(nullptr, exeName, pe.szExeFile, MAX_PATH);
        entry.name = exeName;
        entry.pid = pe.th32ProcessID;

        HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_ALL_ACCESS, FALSE, entry.pid);
        if (!hProc) continue;

        // Memory usage
        PROCESS_MEMORY_COUNTERS pmc;
        if (GetProcessMemoryInfo(hProc, &pmc, sizeof(pmc))) {
            entry.memoryUsage = pmc.WorkingSetSize;
        }

        // Is 64-bit
        BOOL wow64;
        if (IsWow64Process(hProc, &wow64)) {
            entry.is64bit = !wow64;
            entry.architecture = wow64 ? "x86" : "x64";
        }

        // Elevation
        HANDLE hToken;
        if (OpenProcessToken(hProc, TOKEN_QUERY, &hToken)) {
            TOKEN_ELEVATION elevation;
            DWORD size;
            if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &size)) {
                entry.isElevated = elevation.TokenIsElevated != 0;
            }
            CloseHandle(hToken);
        }

        // Load module info
        HMODULE hMods[1024];
        DWORD cbNeeded;
        if (EnumProcessModules(hProc, hMods, sizeof(hMods), &cbNeeded)) {
            for (size_t i = 0; i < (cbNeeded / sizeof(HMODULE)); ++i) {
                TCHAR modName[MAX_PATH];
                if (GetModuleBaseName(hProc, hMods[i], modName, sizeof(modName) / sizeof(TCHAR))) {
                    char modAnsi[MAX_PATH];
                    wcstombs_s(nullptr, modAnsi, modName, MAX_PATH);
                    std::string modStr = modAnsi;
                    entry.modules.push_back(modStr);

                    // Engine heuristics
                    if (modStr.find("UnityPlayer") != std::string::npos) entry.engine = "Unity";
                    if (modStr.find("GameAssembly") != std::string::npos) entry.engine = "Unity (IL2CPP)";
                    if (modStr.find("mono") != std::string::npos) entry.engine = "Unity (Mono)";
                    if (modStr.find("UE4") != std::string::npos || modStr.find("UE5") != std::string::npos) entry.engine = "Unreal Engine";

                    // Protection heuristics
                    if (modStr.find("easyanticheat") != std::string::npos || modStr.find("EAC") != std::string::npos)
                        entry.protection = "EAC";
                    else if (modStr.find("BEDaisy") != std::string::npos || modStr.find("battlEye") != std::string::npos)
                        entry.protection = "BattlEye";
                    else if (modStr.find("VMProtect") != std::string::npos)
                        entry.protection = "VMProtect";
                    else if (modStr.find("Themida") != std::string::npos)
                        entry.protection = "Themida";
                }
            }

            // Entry point & base address (main module only)
            MODULEINFO mi;
            if (GetModuleInformation(hProc, hMods[0], &mi, sizeof(mi))) {
                entry.imageBase = reinterpret_cast<uintptr_t>(mi.lpBaseOfDll);
                entry.entryPoint = reinterpret_cast<uintptr_t>(mi.EntryPoint);
            }
        }

        // Runtime
        FILETIME create, exit, kernel, user;
        if (GetProcessTimes(hProc, &create, &exit, &kernel, &user)) {
            ULARGE_INTEGER uli;
            uli.LowPart = create.dwLowDateTime;
            uli.HighPart = create.dwHighDateTime;
            entry.startTime = std::chrono::system_clock::time_point(
                std::chrono::duration_cast<std::chrono::system_clock::duration>(
                    std::chrono::nanoseconds(uli.QuadPart * 100)));
        }

        CloseHandle(hProc);
        processList.push_back(entry);
    } while (Process32Next(snapshot, &pe));

    CloseHandle(snapshot);

    // Optional sort by memory usage descending
    std::sort(processList.begin(), processList.end(), [](const ProcEntry& a, const ProcEntry& b) {
        return a.memoryUsage > b.memoryUsage;
        });

    processListScanned = true;
}





void DrawProcessSelectorUI() {
    static char processFilter[256] = "";
    static std::vector<int> filteredIndexMap;
    static int selectedRow = -1;
    static bool sortByMemory = true;

    float totalHeight = ImGui::GetContentRegionAvail().y;
    float halfHeight = totalHeight * 0.5f;

    // TOP HALF = PROCESS TABLE
    ImGui::BeginChild("ProcessSection", ImVec2(0, halfHeight), true);

    ImGui::Checkbox("Sort by memory", &sortByMemory);
    ImGui::SameLine();
    ImGui::Text("Welcome, Collin. Time to melt some memory.");

    ImGui::InputTextWithHint("##Filter", "Search processes...", processFilter, IM_ARRAYSIZE(processFilter));
    ImGui::SameLine();
    if (ImGui::Button("X")) processFilter[0] = '\0';

    ImGui::Separator();

    std::sort(processList.begin(), processList.end(), [&](const ProcEntry& a, const ProcEntry& b) {
        if (a.architecture == "K" || a.architecture == "P") return false;
        if (b.architecture == "K" || b.architecture == "P") return true;
        return sortByMemory ? a.memoryUsage > b.memoryUsage : a.name < b.name;
        });

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
                if (nameLower.find(filterLower) == std::string::npos) continue;
            }

            filteredIndexMap.push_back(i);
            ImGui::TableNextRow();

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
                if (ImGui::IsMouseDoubleClicked(0)) {
                    // TODO: Attach logic here
                }
            }

            ImGui::TableSetColumnIndex(1);
            ImGui::Text("%zu MB", p.memoryUsage / (1024 * 1024));

            ImGui::TableSetColumnIndex(2);
            ImVec4 color = ImVec4(1, 1, 1, 1);
            if (p.architecture == "x64") color = ImVec4(0.4f, 1.0f, 0.4f, 1.0f);
            else if (p.architecture == "x86") color = ImVec4(1.0f, 1.0f, 0.4f, 1.0f);
            else if (p.architecture == "K" || p.architecture == "P") color = ImVec4(0.9f, 0.5f, 0.5f, 1.0f);
            ImGui::TextColored(color, "%s", p.architecture.c_str());

            ImGui::TableSetColumnIndex(3);
            ImGui::Text("%lu", p.threadCount);
        }

        ImGui::EndTable();
    }

    ImGui::EndChild();

    // BOTTOM HALF = MEMORY TOOLS + ATTACH BUTTON
    ImGui::BeginChild("MemorySection", ImVec2(0, 0), true); // Remaining space

    if (targetPID != 0) {
        ImGui::Text("Selected: %s (PID: %lu)", selectedProcessName.c_str(), targetPID);
        if (ImGui::Button("Attach to Process", ImVec2(-1, 0))) {
            // TODO: Implement attach logic
        }
    }

    ImGui::Separator();
    ImGui::Text("🧠 Memory tools will go here.");
    ImGui::Text("• Placeholder space for scanning, region maps, etc.");
    ImGui::Text("• Auto attach flag? Memory region selector?");

    ImGui::EndChild();
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
