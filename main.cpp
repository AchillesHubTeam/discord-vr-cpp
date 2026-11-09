// Discord VR Status - Native C++ (DaXcess logic)
// OAuth2 PKCE + headless session loop, no external deps, WinHTTP + BCrypt only.
// Compile: cl /std:c++17 /EHsc /O2 main.cpp /link winhttp.lib bcrypt.lib /SUBSYSTEM:WINDOWS
#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <ctime>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "bcrypt.lib")

static const char* META_APP_ID = "1417273808645259344";
static const char* REDIRECT_URL = "https://oculus.com/oauth_account_linking/login_redirect";
static const char* TOKEN_HOST = L"discord.com";
static const wchar_t* TOKEN_PATH = L"/api/v10/oauth2/token";
static const wchar_t* HEADLESS_PATH = L"/api/v10/users/@me/headless-sessions";
static const wchar_t* HEADLESS_DELETE_PATH = L"/api/v10/users/@me/headless-sessions/delete";

// ---------- utils ----------
static std::wstring GetExeDir() {
    wchar_t buf[MAX_PATH];
    GetModuleFileNameW(nullptr, buf, MAX_PATH);
    std::wstring p(buf);
    size_t pos = p.find_last_of(L"\\/");
    return (pos == std::wstring::npos) ? L"." : p.substr(0, pos);
}
static std::wstring GetExePath() {
    wchar_t buf[MAX_PATH];
    GetModuleFileNameW(nullptr, buf, MAX_PATH);
    return std::wstring(buf);
}
static std::string UrlEncode(const std::string& s) {
    std::string out;
    char hex[4];
    for (unsigned char c : s) {
        if (isalnum(c) || c=='-'||c=='_'||c=='.'||c=='~') out += c;
        else { snprintf(hex, sizeof(hex), "%%%02X", c); out += hex; }
    }
    return out;
}
static std::string Base64Url(const std::vector<unsigned char>& in) {
    static const char* B = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    for (size_t i=0;i<in.size();i+=3) {
        int rem = (int)in.size() - (int)i;
        unsigned v = in[i] << 16;
        if (rem>1) v |= in[i+1] << 8;
        if (rem>2) v |= in[i+2];
        out += B[(v>>18)&63]; out += B[(v>>12)&63];
        out += (rem>1? B[(v>>6)&63] : '=');
        out += (rem>2? B[v&63] : '=');
    }
    while(!out.empty() && out.back()=='=') out.pop_back();
    for(char&c: out){ if(c=='+')c='-'; if(c=='/')c='_'; }
    return out;
}
static std::vector<unsigned char> Sha256(const std::string& s) {
    std::vector<unsigned char> out(32);
    BCRYPT_ALG_HANDLE hAlg=nullptr; BCRYPT_HASH_HANDLE hHash=nullptr;
    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, nullptr, 0);
    BCryptHashData(hHash, (PUCHAR)s.data(), (ULONG)s.size(), 0);
    ULONG len=0; BCryptFinishHash(hHash, out.data(), 32, &len);
    BCryptDestroyHash(hHash); BCryptCloseAlgorithmProvider(hAlg,0);
    return out;
}
static std::string RandomToken(int bytes) {
    std::vector<unsigned char> b(bytes);
    BCryptGenRandom(nullptr, b.data(), bytes, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return Base64Url(b);
}
static bool HttpPost(const wchar_t* host, const wchar_t* path, const std::string& body, const std::string& contentType, const std::string& authHeader, std::string& resp) {
    HINTERNET hSess = WinHttpOpen(L"DiscordVR/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if(!hSess) return false;
    HINTERNET hConn = WinHttpConnect(hSess, host, INTERNET_DEFAULT_HTTPS_PORT, 0);
    HINTERNET hReq = WinHttpOpenRequest(hConn, L"POST", path, nullptr, WINHTTP_WIN32_PROXY, WINHTTP_FLAG_SECURE);
    std::wstring hdr = L"Content-Type: ";
    std::wstring ct(contentType.begin(), contentType.end());
    hdr += ct;
    if(!authHeader.empty()){
        std::wstring ah = L"\r\nAuthorization: Bearer ";
        ah += std::wstring(authHeader.begin(), authHeader.end());
        hdr += ah;
    }
    WinHttpSendRequest(hReq, hdr.c_str(), -1, (LPVOID)body.data(), (DWORD)body.size(), (DWORD)body.size(), 0);
    WinHttpReceiveResponse(hReq, nullptr);
    DWORD status=0, sz=sizeof(status);
    WinHttpQueryHeaders(hReq, WINHTTP_QUERY_STATUS_CODE|WINHTTP_QUERY_FLAG_NUMBER, nullptr, &status, &sz, nullptr);
    resp.clear();
    DWORD avail=0;
    do {
        DWORD got=0;
        WinHttpQueryDataAvailable(hReq, &avail);
        if(avail==0) break;
        std::vector<char> buf(avail);
        WinHttpReadData(hReq, buf.data(), avail, &got);
        resp.append(buf.data(), got);
    } while(avail>0);
    WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSess);
    return status>=200 && status<300;
}
static std::string JsonGet(const std::string& j, const std::string& key) {
    std::string pat="\""+key+"\"";
    size_t p=j.find(pat); if(p==std::string::npos) return "";
    p=j.find(':', p); if(p==std::string::npos) return "";
    p=j.find('"', p); if(p==std::string::npos) return "";
    size_t e=j.find('"', p+1); if(e==std::string::npos) return "";
    return j.substr(p+1, e-p-1);
}
static long long JsonGetNum(const std::string& j, const std::string& key) {
    std::string pat="\""+key+"\"";
    size_t p=j.find(pat); if(p==std::string::npos) return 0;
    p=j.find(':', p); if(p==std::string::npos) return 0;
    while(p<j.size() && (j[p]==' '||j[p]=='\t'||j[p]=='\n'||j[p]=='\r')) p++;
    long long v=0; while(p<j.size() && isdigit((unsigned char)j[p])){ v=v*10+(j[p]-'0'); p++; }
    return v;
}
static std::string ParseQueryParam(const std::string& url, const std::string& key) {
    std::string pat=key+"=";
    size_t p=url.find(pat); if(p==std::string::npos) return "";
    p+=pat.size();
    size_t e=url.find('&', p);
    if(e==std::string::npos) e=url.find(' ', p);
    if(e==std::string::npos) e=url.size();
    return url.substr(p, e-p);
}

// ---------- auth ----------
struct Auth { std::string access, refresh; long long expires_unix=0; };
static std::wstring AuthPath(){ return GetExeDir() + L"\\auth.json"; }
static bool LoadAuth(Auth& a){
    std::ifstream f(AuthPath()); if(!f) return false;
    std::stringstream ss; ss<<f.rdbuf(); std::string j=ss.str();
    a.access=JsonGet(j,"access_token");
    a.refresh=JsonGet(j,"refresh_token");
    a.expires_unix=JsonGetNum(j,"expires_unix");
    return !a.access.empty();
}
static void SaveAuth(const Auth& a){
    std::ofstream f(AuthPath());
    f<<"{\"access_token\":\""<<a.access<<"\",\"refresh_token\":\""<<a.refresh<<"\",\"expires_unix\":"<<a.expires_unix<<"}";
}
static void RegisterStartup(){
    std::wstring exe=GetExePath();
    std::wstring val=L"\""+exe+L"\"";
    HKEY h=nullptr;
    if(RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &h)==ERROR_SUCCESS){
        RegSetValueExW(h, L"DiscordVRStatus", 0, REG_SZ, (BYTE*)val.c_str(), (DWORD)((val.size()+1)*sizeof(wchar_t)));
        RegCloseKey(h);
    }
}

// ---------- oauth ----------
static bool ExchangeCode(const std::string& code, const std::string& verifier, Auth& out){
    std::string body="grant_type=authorization_code&code="+UrlEncode(code)+"&redirect_uri="+UrlEncode(REDIRECT_URL)+"&client_id="+std::string(META_APP_ID)+"&code_verifier="+UrlEncode(verifier);
    std::string resp;
    if(!HttpPost(TOKEN_HOST, TOKEN_PATH, body, "application/x-www-form-urlencoded", "", resp)) return false;
    out.access=JsonGet(resp,"access_token");
    out.refresh=JsonGet(resp,"refresh_token");
    long long exp=JsonGetNum(resp,"expires_in"); if(exp==0) exp=3600;
    out.expires_unix=(long long)time(nullptr)+exp;
    SaveAuth(out); return !out.access.empty();
}
static bool Refresh(Auth& a){
    std::string body="grant_type=refresh_token&refresh_token="+UrlEncode(a.refresh)+"&client_id="+std::string(META_APP_ID);
    std::string resp;
    if(!HttpPost(TOKEN_HOST, TOKEN_PATH, body, "application/x-www-form-urlencoded", "", resp)) return false;
    a.access=JsonGet(resp,"access_token");
    std::string nr=JsonGet(resp,"refresh_token"); if(!nr.empty()) a.refresh=nr;
    long long exp=JsonGetNum(resp,"expires_in"); if(exp==0) exp=3600;
    a.expires_unix=(long long)time(nullptr)+exp;
    SaveAuth(a); return !a.access.empty();
}
static bool InteractiveLogin(Auth& out){
    std::string verifier=RandomToken(64); if(verifier.size()>128) verifier.resize(128);
    std::string challenge=Base64Url(Sha256(verifier));
    std::string state=RandomToken(16);
    std::string url="https://discord.com/oauth2/authorize?client_id="+std::string(META_APP_ID)+"&redirect_uri="+UrlEncode(REDIRECT_URL)+"&response_type=code&scope=identify%20activities.read%20activities.write&state="+UrlEncode(state)+"&code_challenge="+UrlEncode(challenge)+"&code_challenge_method=S256";
    std::cout<<"Open this URL in your browser:\n"<<url<<"\nAuthorize, then paste the resulting URL here:\n> ";
    std::string pasted; std::getline(std::cin, pasted);
    std::string code=ParseQueryParam(pasted,"code");
    if(code.empty()) return false;
    return ExchangeCode(code, verifier, out);
}

// ---------- headless ----------
static std::string g_sessionToken;
static Auth g_auth;
static bool UpdateStatus(){
    std::string body="{\"activities\":[{\"name\":\"~~\",\"application_id\":\""+std::string(META_APP_ID)+"\",\"type\":6,\"platform\":\"meta_quest\"}]}";
    if(!g_sessionToken.empty()){
        body="{\"activities\":[{\"name\":\"~~\",\"application_id\":\""+std::string(META_APP_ID)+"\",\"type\":6,\"platform\":\"meta_quest\"}],\"token\":\""+g_sessionToken+"\"}";
    }
    std::string resp;
    if(!HttpPost(TOKEN_HOST, HEADLESS_PATH, body, "application/json", g_auth.access, resp)) return false;
    g_sessionToken=JsonGet(resp,"token");
    return true;
}
static void DeleteStatus(){
    if(g_sessionToken.empty()) return;
    std::string resp;
    std::string body="{\"token\":\""+g_sessionToken+"\"}";
    HttpPost(TOKEN_HOST, HEADLESS_DELETE_PATH, body, "application/json", g_auth.access, resp);
}

int APIENTRY WinMain(HINSTANCE, HINSTANCE, LPSTR, int){
    bool hasAuth=LoadAuth(g_auth);
    if(!hasAuth){
        AllocConsole();
        freopen("CONIN$", "r", stdin);
        freopen("CONOUT$", "w", stdout);
        std::cout<<"Discord VR Status\nOpen the URL, authorize, then paste the URL.\n";
        if(!InteractiveLogin(g_auth)){
            std::cout<<"Login failed.\n"; Sleep(3000); return 1;
        }
        std::cout<<"Done. VR status active.\n";
        RegisterStartup();
        // keep console open while running first time; user can Ctrl+C
        // loop below runs in this console
    } else {
        RegisterStartup();
        // silent background mode
    }
    while(true){
        if(g_auth.expires_unix < (long long)time(nullptr)+300){
            Refresh(g_auth);
        }
        UpdateStatus();
        Sleep(60000);
    }
    return 0;
}
