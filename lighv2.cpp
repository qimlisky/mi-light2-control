#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <stdexcept>
#include <cstring>
#include <cstdint>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "bcrypt.lib")

// ===== Device config =====
const char* LAMP_IP    = "192.168.1.179";
const char* TOKEN_HEX  = "d1311dcc233072032302d78cda2e6c4a"; // 32-char hex
const char* DEVICE_DID = "847276450";
// =========================
// xiaomi.light.lamp31 MIoT property map
//   siid=2 piid=1  bool          power  (true / false)
//   siid=2 piid=2  uint8  1-100  brightness (%)
//   siid=2 piid=3  uint32 2700-6500  color temp (K)

const uint16_t MIIO_PORT         = 54321;
const DWORD    SOCKET_TIMEOUT_MS = 5000;

#define DEBUG 1

// ============================================================
// Utilities
// ============================================================

#define CHECK_NT(expr, msg) \
    do { NTSTATUS _s=(expr); if(!BCRYPT_SUCCESS(_s)){ \
        std::ostringstream _e; _e<<(msg)<<" NTSTATUS=0x"<<std::hex<<_s; \
        throw std::runtime_error(_e.str()); } } while(0)

std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    if (hex.size() != 32)
        throw std::invalid_argument("Token must be 32 hex chars");
    std::vector<uint8_t> out(16);
    for (int i = 0; i < 16; ++i) {
        char buf[3] = { hex[i*2], hex[i*2+1], '\0' };
        out[i] = (uint8_t)std::strtol(buf, nullptr, 16);
    }
    return out;
}

std::string bytes_to_hex(const uint8_t* d, size_t n) {
    const char* h = "0123456789abcdef";
    std::string s; s.reserve(n*2);
    for (size_t i=0;i<n;++i){ s+=h[d[i]>>4]; s+=h[d[i]&0xF]; }
    return s;
}

// ============================================================
// Crypto
// ============================================================

std::vector<uint8_t> md5(const uint8_t* data, size_t len) {
    BCRYPT_ALG_HANDLE  hA=nullptr; BCRYPT_HASH_HANDLE hH=nullptr;
    CHECK_NT(BCryptOpenAlgorithmProvider(&hA,BCRYPT_MD5_ALGORITHM,nullptr,0),"md5 open");
    CHECK_NT(BCryptCreateHash(hA,&hH,nullptr,0,nullptr,0,0),"md5 create");
    CHECK_NT(BCryptHashData(hH,const_cast<PUCHAR>(data),(ULONG)len,0),"md5 data");
    std::vector<uint8_t> d(16);
    CHECK_NT(BCryptFinishHash(hH,d.data(),16,0),"md5 finish");
    BCryptDestroyHash(hH); BCryptCloseAlgorithmProvider(hA,0);
    return d;
}

std::vector<uint8_t> md5_cat(const uint8_t* a,size_t aL,const uint8_t* b,size_t bL){
    std::vector<uint8_t> buf(aL+bL);
    memcpy(buf.data(),a,aL); memcpy(buf.data()+aL,b,bL);
    return md5(buf.data(),buf.size());
}

// ============================================================
// AES-128-CBC
// ============================================================

std::vector<uint8_t> aes_encrypt(const std::string& plain,
                                  const std::vector<uint8_t>& key,
                                  const std::vector<uint8_t>& iv) {
    BCRYPT_ALG_HANDLE hA=nullptr; BCRYPT_KEY_HANDLE hK=nullptr;
    CHECK_NT(BCryptOpenAlgorithmProvider(&hA,BCRYPT_AES_ALGORITHM,nullptr,0),"aes open");
    CHECK_NT(BCryptSetProperty(hA,BCRYPT_CHAINING_MODE,(PUCHAR)BCRYPT_CHAIN_MODE_CBC,
        sizeof(BCRYPT_CHAIN_MODE_CBC),0),"aes cbc");
    CHECK_NT(BCryptGenerateSymmetricKey(hA,&hK,nullptr,0,
        const_cast<PUCHAR>(key.data()),(ULONG)key.size(),0),"aes key");
    ULONG cbC=((ULONG)plain.size()/16+1)*16;
    uint8_t ivc[16]; memcpy(ivc,iv.data(),16);
    std::vector<uint8_t> c(cbC); ULONG cbO=0;
    CHECK_NT(BCryptEncrypt(hK,(PUCHAR)plain.data(),(ULONG)plain.size(),nullptr,
        ivc,16,c.data(),cbC,&cbO,BCRYPT_BLOCK_PADDING),"aes enc");
    c.resize(cbO); BCryptDestroyKey(hK); BCryptCloseAlgorithmProvider(hA,0);
    return c;
}

std::string aes_decrypt(const uint8_t* data,size_t dLen,
                        const std::vector<uint8_t>& key,
                        const std::vector<uint8_t>& iv) {
    BCRYPT_ALG_HANDLE hA=nullptr; BCRYPT_KEY_HANDLE hK=nullptr;
    CHECK_NT(BCryptOpenAlgorithmProvider(&hA,BCRYPT_AES_ALGORITHM,nullptr,0),"aes open");
    CHECK_NT(BCryptSetProperty(hA,BCRYPT_CHAINING_MODE,(PUCHAR)BCRYPT_CHAIN_MODE_CBC,
        sizeof(BCRYPT_CHAIN_MODE_CBC),0),"aes cbc");
    CHECK_NT(BCryptGenerateSymmetricKey(hA,&hK,nullptr,0,
        const_cast<PUCHAR>(key.data()),(ULONG)key.size(),0),"aes key");
    ULONG cbP=(ULONG)dLen;
    uint8_t ivc[16]; memcpy(ivc,iv.data(),16);
    std::vector<uint8_t> p(cbP); ULONG cbO=0;
    CHECK_NT(BCryptDecrypt(hK,const_cast<PUCHAR>(data),(ULONG)dLen,nullptr,
        ivc,16,p.data(),cbP,&cbO,BCRYPT_BLOCK_PADDING),"aes dec");
    BCryptDestroyKey(hK); BCryptCloseAlgorithmProvider(hA,0);
    return std::string((char*)p.data(),cbO);
}

// ============================================================
// MiIO packet
// Checksum = MD5(header[0..16) + token_raw + enc_payload)
// ============================================================

std::vector<uint8_t> build_packet(const std::string& json,
                                   const std::vector<uint8_t>& token,  // raw 16 bytes
                                   const std::vector<uint8_t>& key,
                                   const std::vector<uint8_t>& iv,
                                   uint32_t device_id, uint32_t ts) {
    auto enc = aes_encrypt(json, key, iv);
    uint16_t pkt_len = (uint16_t)(32 + enc.size());

    uint8_t hdr[32]={};
    hdr[0]=0x21; hdr[1]=0x31;
    hdr[2]=(pkt_len>>8)&0xFF; hdr[3]=pkt_len&0xFF;
    // bytes 4-7: unknown, leave 0
    hdr[8] =(device_id>>24)&0xFF; hdr[9] =(device_id>>16)&0xFF;
    hdr[10]=(device_id>> 8)&0xFF; hdr[11]= device_id     &0xFF;
    hdr[12]=(ts>>24)&0xFF; hdr[13]=(ts>>16)&0xFF;
    hdr[14]=(ts>> 8)&0xFF; hdr[15]= ts     &0xFF;
    // bytes 16-31: checksum placeholder (zeros)

    // checksum = MD5(hdr[0..16) + token_raw + encrypted_payload)
    std::vector<uint8_t> cs_buf(16 + 16 + enc.size());
    memcpy(cs_buf.data(),      hdr,         16);
    memcpy(cs_buf.data()+16,   token.data(),16);
    memcpy(cs_buf.data()+32,   enc.data(),  enc.size());
    auto cksum = md5(cs_buf.data(), cs_buf.size());
    memcpy(hdr+16, cksum.data(), 16);

    std::vector<uint8_t> pkt(32+enc.size());
    memcpy(pkt.data(),    hdr,       32);
    memcpy(pkt.data()+32, enc.data(),enc.size());
    return pkt;
}

// ============================================================
// Session
// ============================================================

struct Session {
    SOCKET               sock   = INVALID_SOCKET;
    sockaddr_in          addr   = {};
    uint32_t             dev_id = 0;
    uint32_t             ts     = 0;
    std::vector<uint8_t> token, key, iv;
    int                  cmd_id = 1;
};

void do_handshake(Session& s) {
    static const uint8_t hello[32]={
        0x21,0x31,0x00,0x20,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
    };
    if (sendto(s.sock,(const char*)hello,32,0,
               (sockaddr*)&s.addr,sizeof(s.addr))==SOCKET_ERROR)
        throw std::runtime_error("sendto handshake failed");

    uint8_t resp[256]={};
    sockaddr_in from{}; int fl=sizeof(from);
    int r=recvfrom(s.sock,(char*)resp,sizeof(resp),0,(sockaddr*)&from,&fl);
    if (r<32) throw std::runtime_error("handshake timeout");

    s.dev_id=((uint32_t)resp[8]<<24)|((uint32_t)resp[9]<<16)|
             ((uint32_t)resp[10]<<8)|(uint32_t)resp[11];
    s.ts    =((uint32_t)resp[12]<<24)|((uint32_t)resp[13]<<16)|
             ((uint32_t)resp[14]<<8)|(uint32_t)resp[15];

#if DEBUG
    std::cout << "[HS] dev_id=" << s.dev_id << "  ts=" << s.ts << "\n";
    std::cout << "[HS] raw=" << bytes_to_hex(resp,(size_t)r) << "\n";
#endif
}

std::string send_cmd(Session& s, const std::string& json) {
#if DEBUG
    std::cout<<"[TX] "<<json<<"\n";
#endif
    auto pkt = build_packet(json, s.token, s.key, s.iv, s.dev_id, s.ts);
    if (sendto(s.sock,(const char*)pkt.data(),(int)pkt.size(),0,
               (sockaddr*)&s.addr,sizeof(s.addr))==SOCKET_ERROR)
        throw std::runtime_error("sendto failed");

    uint8_t resp[4096]={};
    sockaddr_in from{}; int fl=sizeof(from);
    int r=recvfrom(s.sock,(char*)resp,sizeof(resp),0,(sockaddr*)&from,&fl);
    if (r==SOCKET_ERROR)
        throw std::runtime_error("recv timeout WSA="+std::to_string(WSAGetLastError()));

    ++s.ts;

    if (r<32||resp[0]!=0x21||resp[1]!=0x31)
        throw std::runtime_error("bad response header");
    if (r==32) return "(heartbeat only)";

    std::string dec = aes_decrypt(resp+32,(size_t)(r-32), s.key, s.iv);
#if DEBUG
    std::cout<<"[RX] "<<dec<<"\n";
#endif
    return dec;
}

// ============================================================
// MIoT command builders
// ============================================================

const std::string DID = DEVICE_DID;

std::string cmd_set(Session& s, int piid, const std::string& val_json) {
    std::ostringstream o;
    o << "{\"id\":"  << s.cmd_id++
      << ",\"method\":\"set_properties\""
      << ",\"params\":[{\"did\":\"" << DID << "\",\"siid\":2"
      << ",\"piid\":"  << piid
      << ",\"value\":" << val_json << "}]}";
    return send_cmd(s, o.str());
}

std::string cmd_get(Session& s) {
    std::ostringstream o;
    o << "{\"id\":"  << s.cmd_id++
      << ",\"method\":\"get_properties\""
      << ",\"params\":["
      << "{\"did\":\"" << DID << "\",\"siid\":2,\"piid\":1},"
      << "{\"did\":\"" << DID << "\",\"siid\":2,\"piid\":2},"
      << "{\"did\":\"" << DID << "\",\"siid\":2,\"piid\":3}"
      << "]}";
    return send_cmd(s, o.str());
}

std::string cmd_info(Session& s) {
    std::ostringstream o;
    o << "{\"id\":" << s.cmd_id++ << ",\"method\":\"miIO.info\",\"params\":[]}";
    return send_cmd(s, o.str());
}

// ============================================================
// JSON helpers
// ============================================================

std::string piid_val(const std::string& j, int piid) {
    std::string needle = "\"piid\":" + std::to_string(piid);
    auto p = j.find(needle);
    while (p != std::string::npos) {
        auto vp = j.find("\"value\":", p);
        auto np = j.find("\"piid\":",  p+1);
        if (vp==std::string::npos||(np!=std::string::npos&&vp>np)){p=np;continue;}
        vp+=8;
        while(vp<j.size()&&j[vp]==' ')++vp;
        char c=j[vp]; size_t e;
        if(c=='"'){e=j.find('"',vp+1);return j.substr(vp+1,e-vp-1);}
        e=j.find_first_of(",}]",vp);
        return j.substr(vp,e-vp);
    }
    return "";
}

void print_status(const std::string& rsp) {
    std::string pw=piid_val(rsp,1), br=piid_val(rsp,2), ct=piid_val(rsp,3);
    std::cout<<"  power      : "<<(pw=="true"?"ON":"OFF")<<"\n";
    if(!br.empty()) std::cout<<"  brightness : "<<br<<"%\n";
    if(!ct.empty()) std::cout<<"  color temp : "<<ct<<"K\n";
}

// ============================================================
// REPL
// ============================================================

void print_help() {
    std::cout
        <<"  on              - turn lamp on\n"
        <<"  off             - turn lamp off\n"
        <<"  bright <1-100>  - set brightness\n"
        <<"  ct <2700-6500>  - set color temperature (K)\n"
        <<"  status          - query current state\n"
        <<"  info            - query device info\n"
        <<"  quit            - exit\n";
}

int main() {
    SetConsoleOutputCP(65001);
    WSADATA wsa; WSAStartup(MAKEWORD(2,2),&wsa);

    Session s;
    try {
        s.token = hex_to_bytes(TOKEN_HEX);
        s.key   = md5(s.token.data(),s.token.size());
        s.iv    = md5_cat(s.key.data(),s.key.size(),s.token.data(),s.token.size());
        std::cout << "key=" << bytes_to_hex(s.key.data(),16)
                  << "\niv =" << bytes_to_hex(s.iv.data(),16) << "\n";

        s.sock=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
        if(s.sock==INVALID_SOCKET) throw std::runtime_error("socket failed");

        DWORD tmo=SOCKET_TIMEOUT_MS;
        setsockopt(s.sock,SOL_SOCKET,SO_RCVTIMEO,(char*)&tmo,sizeof(tmo));
        setsockopt(s.sock,SOL_SOCKET,SO_SNDTIMEO,(char*)&tmo,sizeof(tmo));

        s.addr.sin_family=AF_INET;
        s.addr.sin_port=htons(MIIO_PORT);
        inet_pton(AF_INET,LAMP_IP,&s.addr.sin_addr);

        std::cout<<"Connecting to "<<LAMP_IP<<" (DID="<<DID<<") ...\n";
        do_handshake(s);
        std::cout<<"Connected.\n\n";
    }
    catch(const std::exception& e){
        std::cerr<<"[ERROR] "<<e.what()<<"\n";
        WSACleanup(); return 1;
    }

    print_help();
    std::string line;
    while(true){
        std::cout<<"\n> ";
        if(!std::getline(std::cin,line)) break;
        while(!line.empty()&&(line.back()=='\r'||line.back()==' '))line.pop_back();
        if(line.empty()) continue;

        std::istringstream iss(line);
        std::string cmd; iss>>cmd;

        try {
            do_handshake(s); // refresh timestamp before every command

            if      (cmd=="quit"||cmd=="exit") break;
            else if (cmd=="on")    { std::cout<<"  "<<cmd_set(s,1,"true") <<"\n"; }
            else if (cmd=="off")   { std::cout<<"  "<<cmd_set(s,1,"false")<<"\n"; }
            else if (cmd=="bright"){
                int v=0; iss>>v;
                if(v<1||v>100){std::cout<<"  range 1-100\n";continue;}
                std::cout<<"  "<<cmd_set(s,2,std::to_string(v))<<"\n";
            }
            else if (cmd=="ct"){
                int v=0; iss>>v;
                if(v<2700||v>6500){std::cout<<"  range 2700-6500\n";continue;}
                std::cout<<"  "<<cmd_set(s,3,std::to_string(v))<<"\n";
            }
            else if (cmd=="status"){ print_status(cmd_get(s)); }
            else if (cmd=="info")  { std::cout<<"  "<<cmd_info(s)<<"\n"; }
            else { std::cout<<"  Unknown command.\n"; print_help(); }
        }
        catch(const std::exception& e){
            std::cerr<<"  [ERROR] "<<e.what()<<"\n";
        }
    }

    closesocket(s.sock);
    WSACleanup();
    return 0;
}