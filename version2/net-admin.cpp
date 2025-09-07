#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <map>
#include <string>
#include <chrono>
#include <thread>
#include <csignal>
#include <cstdint>
#include <iomanip>
#include <arpa/inet.h>
#include <unistd.h>
#include <fmt/format.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

// ==================== Constants ====================

const std::map<std::string, std::string> COLORS = {
    {"ESTABLISHED", "\033[32m"}, // Green
    {"SYN_SENT", "\033[31m"},    // Red
    {"SYN_RECV", "\033[31m"},    // Red
    {"LISTEN", "\033[33m"},      // Yellow
    {"CLOSE", "\033[31m"},       // Red
    {"DEFAULT", "\033[0m"},      // Reset
    {"HEADER", "\033[1;34m"},    // Bold Blue
    {"TIMESTAMP", "\033[1;36m"}, // Bold Cyan
    {"SEPARATOR", "\033[1;30m"}  // Light Grey
};

const std::map<std::string, std::string> TCP_STATES = {
    {"01", "ESTABLISHED"}, {"02", "SYN_SENT"}, {"03", "SYN_RECV"}, {"04", "FIN_WAIT1"},
    {"05", "FIN_WAIT2"}, {"06", "TIME_WAIT"}, {"07", "CLOSE"}, {"08", "CLOSE_WAIT"},
    {"09", "LAST_ACK"}, {"0A", "LISTEN"}, {"0B", "CLOSING"}
};

// ==================== Data Struct ====================

struct Connection {
    std::string protocol;
    std::string state;
    std::string local_address;
    uint16_t local_port;
    std::string peer_address;
    uint16_t peer_port;
};

// JSON serialization
void to_json(json& j, const Connection& conn) {
    j = json{
        {"protocol", conn.protocol},
        {"state", conn.state},
        {"local_address", conn.local_address},
        {"local_port", conn.local_port},
        {"peer_address", conn.peer_address},
        {"peer_port", conn.peer_port}
    };
}

// ==================== Helpers ====================

uint16_t hex_to_uint16(const std::string& hex) {
    try {
        return static_cast<uint16_t>(std::stoul(hex, nullptr, 16));
    } catch (...) {
        return 0;
    }
}

std::string parse_ipv4(const std::string& hex_ip) {
    if (hex_ip.size() != 8) return "0.0.0.0";
    uint32_t addr;
    std::stringstream ss;
    ss << std::hex << hex_ip;
    ss >> addr;
    addr = htonl(addr);
    char buf[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &addr, buf, sizeof(buf))) {
        return buf;
    }
    return "0.0.0.0";
}

std::string parse_ipv6(const std::string& hex_ip) {
    if (hex_ip.size() != 32) return "::";
    uint8_t bytes[16];
    for (int i = 0; i < 16; i++) {
        std::string byte_str = hex_ip.substr(i * 2, 2);
        bytes[15 - i] = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
    }
    char buf[INET6_ADDRSTRLEN];
    if (inet_ntop(AF_INET6, bytes, buf, sizeof(buf))) {
        return buf;
    }
    return "::";
}

std::vector<std::string> split(const std::string& s, char delim) {
    std::vector<std::string> result;
    std::istringstream iss(s);
    std::string item;
    while (std::getline(iss, item, delim)) {
        result.push_back(item);
    }
    return result;
}

// ==================== Core ====================

std::vector<Connection> read_tcp_connections(
    const std::string& protocol,
    const std::string& filter_state,
    const std::string& filter_ip,
    const int filter_port
) {
    std::vector<Connection> connections;
    std::ifstream file("/proc/net/" + protocol);
    if (!file.is_open()) {
        std::cerr << "Error: Cannot open /proc/net/" << protocol << std::endl;
        return connections;
    }

    std::string line;
    std::getline(file, line); // skip header

    while (std::getline(file, line)) {
        std::istringstream iss(line);
        std::vector<std::string> fields;
        std::string field;
        while (iss >> field) fields.push_back(field);

        if (fields.size() < 4) continue;

        auto local_parts = split(fields[1], ':');
        auto peer_parts = split(fields[2], ':');
        if (local_parts.size() != 2 || peer_parts.size() != 2) continue;

        std::string state = TCP_STATES.count(fields[3]) ? TCP_STATES.at(fields[3]) : "UNKNOWN";

        uint16_t local_port = hex_to_uint16(local_parts[1]);
        uint16_t peer_port = hex_to_uint16(peer_parts[1]);
        std::string local_ip = (protocol == "tcp6") ? parse_ipv6(local_parts[0]) : parse_ipv4(local_parts[0]);
        std::string peer_ip = (protocol == "tcp6") ? parse_ipv6(peer_parts[0]) : parse_ipv4(peer_parts[0]);

        if (!filter_state.empty() && state != filter_state) continue;
        if (!filter_ip.empty() && filter_ip != local_ip && filter_ip != peer_ip) continue;
        if (filter_port != -1 && filter_port != local_port && filter_port != peer_port) continue;

        connections.push_back({protocol, state, local_ip, local_port, peer_ip, peer_port});
    }
    return connections;
}

std::string get_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&t), "%F %T");
    return ss.str();
}

void display_connections(
    const std::vector<Connection>& connections,
    const std::string& output_format,
    bool use_color
) {
    if (output_format == "json") {
        json j = connections;
        std::cout << j.dump(2) << std::endl;
        return;
    }

    std::cout << fmt::format("{}Timestamp: {}{}", 
        use_color ? COLORS.at("TIMESTAMP") : "", 
        get_timestamp(), 
        use_color ? COLORS.at("DEFAULT") : "") << "\n";

    std::cout << fmt::format("{}Netid  State          Local Address:Port     Peer Address:Port{}", 
        use_color ? COLORS.at("HEADER") : "", 
        use_color ? COLORS.at("DEFAULT") : "") << "\n";

    std::cout << fmt::format("{}={}{}", 
        use_color ? COLORS.at("SEPARATOR") : "", 
        std::string(70, '='), 
        use_color ? COLORS.at("DEFAULT") : "") << "\n";

    for (const auto& conn : connections) {
        std::string color = use_color && COLORS.count(conn.state) ? COLORS.at(conn.state) : COLORS.at("DEFAULT");
        std::cout << fmt::format("{:<6} {}{:<14}{} {}:{:<5}   {}:{:<5}",
            conn.protocol, color, conn.state, use_color ? COLORS.at("DEFAULT") : "",
            conn.local_address, conn.local_port, conn.peer_address, conn.peer_port
        ) << "\n";

        std::cout << fmt::format("{}{}{}", 
            use_color ? COLORS.at("SEPARATOR") : "", 
            std::string(70, '-'), 
            use_color ? COLORS.at("DEFAULT") : "") << "\n";
    }
}

// ==================== Signal Handling ====================

static volatile sig_atomic_t running = 1;
void signal_handler(int) { running = 0; }

void watch_tcp_connections(
    int interval,
    const std::string& filter_state,
    const std::string& filter_ip,
    int filter_port,
    const std::string& output_format
) {
    bool use_color = isatty(STDOUT_FILENO);
    signal(SIGINT, signal_handler);

    while (running) {
        auto conns = read_tcp_connections("tcp", filter_state, filter_ip, filter_port);
        auto conns6 = read_tcp_connections("tcp6", filter_state, filter_ip, filter_port);
        conns.insert(conns.end(), conns6.begin(), conns6.end());

        display_connections(conns, output_format, use_color);
        std::this_thread::sleep_for(std::chrono::seconds(interval));
    }
    std::cerr << "Exiting TCP watcher." << std::endl;
}

// ==================== Main ====================

int main(int argc, char* argv[]) {
#ifndef __linux__
    std::cerr << "This program requires Linux with /proc/net." << std::endl;
    return 1;
#endif

    int interval = 2;
    std::string filter_state, filter_ip, output_format = "text";
    int filter_port = -1;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        try {
            if (arg == "--interval" && i + 1 < argc) interval = std::stoi(argv[++i]);
            else if (arg == "--filter-state" && i + 1 < argc) filter_state = argv[++i];
            else if (arg == "--filter-ip" && i + 1 < argc) filter_ip = argv[++i];
            else if (arg == "--filter-port" && i + 1 < argc) filter_port = std::stoi(argv[++i]);
            else if (arg == "--output-format" && i + 1 < argc) {
                output_format = argv[++i];
                if (output_format != "text" && output_format != "json")
                    throw std::invalid_argument("Invalid format");
            } else {
                throw std::invalid_argument("Invalid argument");
            }
        } catch (...) {
            std::cerr << "Usage: " << argv[0] 
                      << " [--interval <seconds>] [--filter-state <state>] [--filter-ip <ip>] "
                      << "[--filter-port <port>] [--output-format <text|json>]\n";
            return 1;
        }
    }

    if (interval <= 0) {
        std::cerr << "Interval must be positive." << std::endl;
        return 1;
    }

    watch_tcp_connections(interval, filter_state, filter_ip, filter_port, output_format);
    return 0;
}
