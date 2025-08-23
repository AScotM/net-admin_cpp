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

using json = nlohmann::basic_json<>;

// Constants
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

// Struct for connection data
struct Connection {
    std::string protocol;
    std::string state;
    std::string local_address;
    uint16_t local_port;
    std::string peer_address;
    uint16_t peer_port;
};

// JSON serialization for Connection struct
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

// Convert hex to decimal for ports
uint16_t hex_to_uint16(const std::string& hex) {
    try {
        return static_cast<uint16_t>(std::stoul(hex, nullptr, 16));
    } catch (const std::exception& e) {
        std::cerr << "Error parsing port: " << hex << std::endl;
        return 0;
    }
}

// Parse IPv4 address (little-endian hex)
std::string parse_ipv4(const std::string& hex_ip) {
    try {
        std::vector<uint8_t> bytes;
        for (size_t i = 0; i < hex_ip.length(); i += 2) {
            bytes.push_back(static_cast<uint8_t>(std::stoul(hex_ip.substr(i, 2), nullptr, 16)));
        }
        std::reverse(bytes.begin(), bytes.end()); // Handle little-endian
        char addr[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, bytes.data(), addr, INET_ADDRSTRLEN)) {
            return addr;
        }
    } catch (const std::exception& e) {
        std::cerr << "Failed to parse IPv4: " << e.what() << std::endl;
    }
    return "0.0.0.0";
}

// Parse IPv6 address (little-endian per 32-bit word)
std::string parse_ipv6(const std::string& hex_ip) {
    try {
        std::vector<uint8_t> bytes;
        for (size_t i = 0; i < hex_ip.length(); i += 2) {
            bytes.push_back(static_cast<uint8_t>(std::stoul(hex_ip.substr(i, 2), nullptr, 16)));
        }
        // Reverse each 32-bit word (8 hex chars)
        std::vector<uint8_t> reversed;
        for (int i = 3; i >= 0; --i) {
            for (int j = 0; j < 4; ++j) {
                reversed.push_back(bytes[i * 4 + j]);
            }
        }
        char addr[INET6_ADDRSTRLEN];
        if (inet_ntop(AF_INET6, reversed.data(), addr, INET6_ADDRSTRLEN)) {
            return addr;
        }
    } catch (const std::exception& e) {
        std::cerr << "Failed to parse IPv6: " << e.what() << std::endl;
    }
    return "::";
}

// Split string by delimiter
std::vector<std::string> split(const std::string& s, char delim) {
    std::vector<std::string> result;
    std::istringstream iss(s);
    std::string item;
    while (std::getline(iss, item, delim)) {
        result.push_back(item);
    }
    return result;
}

// Read TCP connections from /proc/net
std::vector<Connection> read_tcp_connections(
    const std::string& protocol,
    const std::string& filter_state,
    const std::string& filter_ip,
    const int filter_port
) {
    std::vector<Connection> connections;
    std::string proc_file = "/proc/net/" + protocol;
    std::ifstream file(proc_file);
    if (!file.is_open()) {
        std::cerr << "Error: " << proc_file << " not found. Are you on a Linux system?" << std::endl;
        return connections;
    }

    std::string line;
    std::getline(file, line); // Skip header
    while (std::getline(file, line)) {
        std::istringstream iss(line);
        std::vector<std::string> fields;
        std::string field;
        while (iss >> field) {
            fields.push_back(field);
        }
        if (fields.size() < 4 || fields[1].find(':') == std::string::npos || fields[2].find(':') == std::string::npos) {
            std::cerr << "Skipping malformed line: " << line << std::endl;
            continue;
        }

        auto local_parts = split(fields[1], ':');
        auto peer_parts = split(fields[2], ':');
        std::string state = TCP_STATES.count(fields[3]) ? TCP_STATES.at(fields[3]) : "UNKNOWN";

        uint16_t local_port = hex_to_uint16(local_parts[1]);
        uint16_t peer_port = hex_to_uint16(peer_parts[1]);
        std::string local_ip = (protocol == "tcp6") ? parse_ipv6(local_parts[0]) : parse_ipv4(local_parts[0]);
        std::string peer_ip = (protocol == "tcp6") ? parse_ipv6(peer_parts[0]) : parse_ipv4(peer_parts[0]);

        // Apply filters
        if (!filter_state.empty() && state != filter_state) continue;
        if (!filter_ip.empty() && filter_ip != local_ip && filter_ip != peer_ip) continue;
        if (filter_port != -1 && filter_port != local_port && filter_port != peer_port) continue;

        connections.push_back({
            protocol, state, local_ip, local_port, peer_ip, peer_port
        });
    }
    return connections;
}

// Get current timestamp
std::string get_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

// Display connections
void display_connections(
    const std::vector<Connection>& connections,
    const std::string& output_format,
    bool use_color
) {
    if (output_format == "json") {
        json j = json::array();
        for (const auto& conn : connections) {
            j.push_back(conn);
        }
        std::cout << j.dump(2) << std::endl;
    } else {
        std::string timestamp = get_timestamp();
        std::string header = fmt::format(
            "{}Netid  State          Local Address:Port     Peer Address:Port{}",
            use_color ? COLORS.at("HEADER") : "", use_color ? COLORS.at("DEFAULT") : ""
        );
        std::string separator = fmt::format(
            "{}={}{}", use_color ? COLORS.at("SEPARATOR") : "", std::string(70, '='), use_color ? COLORS.at("DEFAULT") : ""
        );

        std::cout << fmt::format(
            "{}Timestamp: {}{}", use_color ? COLORS.at("TIMESTAMP") : "", timestamp, use_color ? COLORS.at("DEFAULT") : ""
        ) << std::endl;
        std::cout << header << std::endl;
        std::cout << separator << std::endl;

        for (const auto& conn : connections) {
            std::string color = use_color && COLORS.count(conn.state) ? COLORS.at(conn.state) : COLORS.at("DEFAULT");
            std::cout << fmt::format(
                "{:<6} {}{:<14}{} {}:{:<5}   {}:{:<5}",
                conn.protocol, color, conn.state, use_color ? COLORS.at("DEFAULT") : "",
                conn.local_address, conn.local_port, conn.peer_address, conn.peer_port
            ) << std::endl;
            std::cout << fmt::format(
                "{}{}{}", use_color ? COLORS.at("SEPARATOR") : "", std::string(70, '-'), use_color ? COLORS.at("DEFAULT") : ""
            ) << std::endl;
        }
        std::cout << separator << std::endl;
    }
}

// Signal handler
static volatile sig_atomic_t running = 1;
void signal_handler(int sig) {
    running = 0;
}

// Watch TCP connections
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
        std::vector<Connection> connections = read_tcp_connections("tcp", filter_state, filter_ip, filter_port);
        auto tcp6_connections = read_tcp_connections("tcp6", filter_state, filter_ip, filter_port);
        connections.insert(connections.end(), tcp6_connections.begin(), tcp6_connections.end());
        display_connections(connections, output_format, use_color);
        std::this_thread::sleep_for(std::chrono::seconds(interval));
    }
    std::cerr << "Exiting TCP connection watcher." << std::endl;
}

int main(int argc, char* argv[]) {
    // Check platform
    #ifndef __linux__
    std::cerr << "This program requires a Linux system with /proc/net." << std::endl;
    return 1;
    #endif

    // Parse arguments
    int interval = 2;
    std::string filter_state;
    std::string filter_ip;
    int filter_port = -1;
    std::string output_format = "text";

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--interval" && i + 1 < argc) {
            interval = std::stoi(argv[++i]);
        } else if (arg == "--filter-state" && i + 1 < argc) {
            filter_state = argv[++i];
            bool valid_state = false;
            for (const auto& state : TCP_STATES) {
                if (state.second == filter_state) {
                    valid_state = true;
                    break;
                }
            }
            if (!valid_state) {
                std::cerr << "Invalid TCP state: " << filter_state << std::endl;
                return 1;
            }
        } else if (arg == "--filter-ip" && i + 1 < argc) {
            filter_ip = argv[++i];
        } else if (arg == "--filter-port" && i + 1 < argc) {
            filter_port = std::stoi(argv[++i]);
        } else if (arg == "--output-format" && i + 1 < argc) {
            output_format = argv[++i];
            if (output_format != "text" && output_format != "json") {
                std::cerr << "Invalid output format: " << output_format << std::endl;
                return 1;
            }
        } else {
            std::cerr << "Usage: " << argv[0] 
                      << " [--interval <seconds>] [--filter-state <state>] [--filter-ip <ip>] [--filter-port <port>] [--output-format <text|json>]" << std::endl;
            return 1;
        }
    }

    if (interval <= 0) {
        std::cerr << "Interval must be a positive integer." << std::endl;
        return 1;
    }

    watch_tcp_connections(interval, filter_state, filter_ip, filter_port, output_format);
    return 0;
}
