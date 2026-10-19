#include <algorithm>
#include <filesystem>
#include <map>
#include <set>
#include <unordered_set>
#include <tuple>
#include <charconv>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <cmath>
#include <numeric>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

#include <arpa/inet.h>
#include <unistd.h>

namespace {

constexpr std::string_view RESET = "\033[0m";
constexpr std::string_view GREEN = "\033[32m";
constexpr std::string_view RED = "\033[31m";
constexpr std::string_view YELLOW = "\033[33m";
constexpr std::string_view BLUE = "\033[1;34m";
constexpr std::string_view CYAN = "\033[1;36m";
constexpr std::string_view GREY = "\033[1;30m";

std::atomic<bool> running{true};

enum class Protocol {
    TCP,
    TCP6,
    ALL
};

enum class OutputFormat {
    TABLE,
    JSON,
    JSONL
};

struct Connection {
    std::string protocol;
    std::string state;
    std::string local_address;
    std::uint16_t local_port{};
    std::string peer_address;
    std::uint16_t peer_port{};
    std::uint32_t uid{};
    std::uint64_t inode{};
};

struct Options {
    bool once{false};
    bool no_color{false};
    int interval{2};
    Protocol protocol{Protocol::ALL};
    OutputFormat format{OutputFormat::TABLE};
    std::optional<std::string> filter_state;
    std::optional<std::string> filter_ip;
    std::optional<std::uint16_t> filter_port;
};

const std::unordered_map<std::string, std::string> TCP_STATES{
    {"01", "ESTABLISHED"},
    {"02", "SYN_SENT"},
    {"03", "SYN_RECV"},
    {"04", "FIN_WAIT1"},
    {"05", "FIN_WAIT2"},
    {"06", "TIME_WAIT"},
    {"07", "CLOSE"},
    {"08", "CLOSE_WAIT"},
    {"09", "LAST_ACK"},
    {"0A", "LISTEN"},
    {"0B", "CLOSING"},
    {"0C", "NEW_SYN_RECV"}
};

void signal_handler(int) {
    running.store(false, std::memory_order_relaxed);
}

std::string uppercase(std::string value) {
    std::transform(
        value.begin(),
        value.end(),
        value.begin(),
        [](unsigned char c) {
            return static_cast<char>(std::toupper(c));
        }
    );
    return value;
}

std::string lowercase(std::string value) {
    std::transform(
        value.begin(),
        value.end(),
        value.begin(),
        [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        }
    );
    return value;
}

std::vector<std::string> split(const std::string& value, char delimiter) {
    std::vector<std::string> result;
    std::istringstream stream(value);
    std::string item;

    while (std::getline(stream, item, delimiter)) {
        result.push_back(item);
    }

    return result;
}

std::uint64_t parse_unsigned(
    const std::string& value,
    int base,
    const std::string& field_name
) {
    if (value.empty()) {
        throw std::runtime_error(field_name + " is empty");
    }

    std::size_t position = 0;

    try {
        const auto parsed = std::stoull(value, &position, base);

        if (position != value.size()) {
            throw std::runtime_error(
                "Invalid " + field_name + ": " + value
            );
        }

        return parsed;
    } catch (const std::invalid_argument&) {
        throw std::runtime_error(
            "Invalid " + field_name + ": " + value
        );
    } catch (const std::out_of_range&) {
        throw std::runtime_error(
            field_name + " out of range: " + value
        );
    }
}

std::uint16_t parse_hex_port(const std::string& value) {
    const auto port = parse_unsigned(value, 16, "port");

    if (port > std::numeric_limits<std::uint16_t>::max()) {
        throw std::runtime_error("Port out of range");
    }

    return static_cast<std::uint16_t>(port);
}

std::string parse_ipv4(const std::string& hex_ip) {
    if (hex_ip.size() != 8) {
        throw std::runtime_error("Invalid IPv4 address field");
    }

    std::array<unsigned char, 4> bytes{};

    for (std::size_t i = 0; i < 4; ++i) {
        const auto byte = parse_unsigned(
            hex_ip.substr(i * 2, 2),
            16,
            "IPv4 byte"
        );

        bytes[3 - i] = static_cast<unsigned char>(byte);
    }

    char buffer[INET_ADDRSTRLEN]{};

    if (
        inet_ntop(
            AF_INET,
            bytes.data(),
            buffer,
            sizeof(buffer)
        ) == nullptr
    ) {
        throw std::runtime_error(
            std::string("inet_ntop IPv4 failed: ") +
            std::strerror(errno)
        );
    }

    return buffer;
}

std::string parse_ipv6(const std::string& hex_ip) {
    if (hex_ip.size() != 32) {
        throw std::runtime_error("Invalid IPv6 address field");
    }

    std::array<unsigned char, 16> bytes{};

    for (std::size_t word = 0; word < 4; ++word) {
        const std::size_t offset = word * 8;

        for (std::size_t byte = 0; byte < 4; ++byte) {
            const std::size_t source =
                offset + (3 - byte) * 2;

            bytes[word * 4 + byte] =
                static_cast<unsigned char>(
                    parse_unsigned(
                        hex_ip.substr(source, 2),
                        16,
                        "IPv6 byte"
                    )
                );
        }
    }

    char buffer[INET6_ADDRSTRLEN]{};

    if (
        inet_ntop(
            AF_INET6,
            bytes.data(),
            buffer,
            sizeof(buffer)
        ) == nullptr
    ) {
        throw std::runtime_error(
            std::string("inet_ntop IPv6 failed: ") +
            std::strerror(errno)
        );
    }

    return buffer;
}

std::string state_from_hex(const std::string& value) {
    const auto iterator = TCP_STATES.find(value);

    if (iterator == TCP_STATES.end()) {
        return "UNKNOWN";
    }

    return iterator->second;
}

bool valid_tcp_state(const std::string& state) {
    return std::any_of(
        TCP_STATES.begin(),
        TCP_STATES.end(),
        [&state](const auto& item) {
            return item.second == state;
        }
    );
}

std::string timestamp() {
    const auto now = std::chrono::system_clock::now();
    const auto raw_time =
        std::chrono::system_clock::to_time_t(now);

    std::tm local{};

    if (localtime_r(&raw_time, &local) == nullptr) {
        return "unknown";
    }

    std::ostringstream output;
    output << std::put_time(&local, "%F %T");

    return output.str();
}

std::string json_escape(const std::string& value) {
    std::ostringstream output;

    for (const unsigned char c : value) {
        switch (c) {
            case '"':
                output << "\\\"";
                break;
            case '\\':
                output << "\\\\";
                break;
            case '\b':
                output << "\\b";
                break;
            case '\f':
                output << "\\f";
                break;
            case '\n':
                output << "\\n";
                break;
            case '\r':
                output << "\\r";
                break;
            case '\t':
                output << "\\t";
                break;
            default:
                if (c < 0x20) {
                    output
                        << "\\u"
                        << std::hex
                        << std::setw(4)
                        << std::setfill('0')
                        << static_cast<int>(c)
                        << std::dec
                        << std::setfill(' ');
                } else {
                    output << static_cast<char>(c);
                }
        }
    }

    return output.str();
}

std::string connection_to_json(const Connection& connection) {
    std::ostringstream output;

    output
        << "{"
        << "\"protocol\":\""
        << json_escape(connection.protocol)
        << "\","
        << "\"state\":\""
        << json_escape(connection.state)
        << "\","
        << "\"local_address\":\""
        << json_escape(connection.local_address)
        << "\","
        << "\"local_port\":"
        << connection.local_port
        << ","
        << "\"peer_address\":\""
        << json_escape(connection.peer_address)
        << "\","
        << "\"peer_port\":"
        << connection.peer_port
        << ","
        << "\"uid\":"
        << connection.uid
        << ","
        << "\"inode\":"
        << connection.inode
        << "}";

    return output.str();
}

std::string endpoint(
    const std::string& address,
    std::uint16_t port
) {
    if (address.find(':') != std::string::npos) {
        return "[" + address + "]:" + std::to_string(port);
    }

    return address + ":" + std::to_string(port);
}

std::string color_for_state(const std::string& state) {
    if (state == "ESTABLISHED") {
        return std::string(GREEN);
    }

    if (
        state == "SYN_SENT" ||
        state == "SYN_RECV" ||
        state == "CLOSE"
    ) {
        return std::string(RED);
    }

    if (state == "LISTEN") {
        return std::string(YELLOW);
    }

    return std::string(RESET);
}

bool connection_matches(
    const Connection& connection,
    const Options& options
) {
    if (
        options.filter_state &&
        connection.state != *options.filter_state
    ) {
        return false;
    }

    if (
        options.filter_ip &&
        connection.local_address != *options.filter_ip &&
        connection.peer_address != *options.filter_ip
    ) {
        return false;
    }

    if (
        options.filter_port &&
        connection.local_port != *options.filter_port &&
        connection.peer_port != *options.filter_port
    ) {
        return false;
    }

    return true;
}

std::vector<Connection> read_tcp_file(
    const std::string& protocol,
    const Options& options
) {
    const std::string path = "/proc/net/" + protocol;

    std::ifstream file(path);

    if (!file) {
        throw std::runtime_error(
            "Cannot open " + path
        );
    }

    std::vector<Connection> connections;
    std::string line;

    std::getline(file, line);

    while (std::getline(file, line)) {
        std::istringstream input(line);
        std::vector<std::string> fields;
        std::string field;

        while (input >> field) {
            fields.push_back(field);
        }

        if (fields.size() < 10) {
            continue;
        }

        const auto local_parts = split(fields[1], ':');
        const auto peer_parts = split(fields[2], ':');

        if (
            local_parts.size() != 2 ||
            peer_parts.size() != 2
        ) {
            continue;
        }

        try {
            Connection connection;

            connection.protocol = protocol;
            connection.state =
                state_from_hex(fields[3]);

            connection.local_port =
                parse_hex_port(local_parts[1]);

            connection.peer_port =
                parse_hex_port(peer_parts[1]);

            if (protocol == "tcp6") {
                connection.local_address =
                    parse_ipv6(local_parts[0]);

                connection.peer_address =
                    parse_ipv6(peer_parts[0]);
            } else {
                connection.local_address =
                    parse_ipv4(local_parts[0]);

                connection.peer_address =
                    parse_ipv4(peer_parts[0]);
            }

            const auto uid =
                parse_unsigned(fields[7], 10, "UID");

            if (
                uid >
                std::numeric_limits<std::uint32_t>::max()
            ) {
                continue;
            }

            connection.uid =
                static_cast<std::uint32_t>(uid);

            connection.inode =
                parse_unsigned(fields[9], 10, "inode");

            if (connection_matches(connection, options)) {
                connections.push_back(
                    std::move(connection)
                );
            }
        } catch (const std::exception&) {
            continue;
        }
    }

    return connections;
}

std::vector<Connection> read_connections(
    const Options& options
) {
    std::vector<Connection> connections;

    auto append = [&connections](
        std::vector<Connection> source
    ) {
        connections.insert(
            connections.end(),
            std::make_move_iterator(source.begin()),
            std::make_move_iterator(source.end())
        );
    };

    if (
        options.protocol == Protocol::TCP ||
        options.protocol == Protocol::ALL
    ) {
        append(read_tcp_file("tcp", options));
    }

    if (
        options.protocol == Protocol::TCP6 ||
        options.protocol == Protocol::ALL
    ) {
        append(read_tcp_file("tcp6", options));
    }

    std::sort(
        connections.begin(),
        connections.end(),
        [](const Connection& left, const Connection& right) {
            if (left.state != right.state) {
                return left.state < right.state;
            }

            if (left.local_address != right.local_address) {
                return left.local_address <
                       right.local_address;
            }

            if (left.local_port != right.local_port) {
                return left.local_port <
                       right.local_port;
            }

            if (left.peer_address != right.peer_address) {
                return left.peer_address <
                       right.peer_address;
            }

            return left.peer_port < right.peer_port;
        }
    );

    return connections;
}

void display_table(
    const std::vector<Connection>& connections,
    bool color
) {
    const std::string current_timestamp = timestamp();

    if (color) {
        std::cout << CYAN;
    }

    std::cout << "Timestamp: " << current_timestamp;

    if (color) {
        std::cout << RESET;
    }

    std::cout << '\n';

    if (color) {
        std::cout << BLUE;
    }

    std::cout
        << std::left
        << std::setw(7) << "Netid"
        << std::setw(14) << "State"
        << std::setw(44) << "Local Address:Port"
        << std::setw(44) << "Peer Address:Port"
        << std::setw(10) << "UID"
        << "Inode";

    if (color) {
        std::cout << RESET;
    }

    std::cout << '\n';

    if (color) {
        std::cout << GREY;
    }

    std::cout << std::string(135, '=');

    if (color) {
        std::cout << RESET;
    }

    std::cout << '\n';

    for (const auto& connection : connections) {
        const auto local = endpoint(
            connection.local_address,
            connection.local_port
        );

        const auto peer = endpoint(
            connection.peer_address,
            connection.peer_port
        );

        std::cout
            << std::left
            << std::setw(7)
            << connection.protocol;

        if (color) {
            std::cout << color_for_state(
                connection.state
            );
        }

        std::cout
            << std::setw(14)
            << connection.state;

        if (color) {
            std::cout << RESET;
        }

        std::cout
            << std::setw(44)
            << local
            << std::setw(44)
            << peer
            << std::setw(10)
            << connection.uid
            << connection.inode
            << '\n';
    }

    std::unordered_map<std::string, std::size_t> counts;

    for (const auto& connection : connections) {
        ++counts[connection.state];
    }

    std::cout << '\n';
    std::cout << "Total: " << connections.size();

    if (!counts.empty()) {
        std::vector<std::pair<std::string, std::size_t>>
            sorted_counts(
                counts.begin(),
                counts.end()
            );

        std::sort(
            sorted_counts.begin(),
            sorted_counts.end()
        );

        std::cout << " | ";

        for (std::size_t i = 0; i < sorted_counts.size(); ++i) {
            if (i > 0) {
                std::cout << ", ";
            }

            std::cout
                << sorted_counts[i].first
                << ": "
                << sorted_counts[i].second;
        }
    }

    std::cout << '\n';
}

void display_json(
    const std::vector<Connection>& connections
) {
    std::cout
        << "{"
        << "\"timestamp\":\""
        << json_escape(timestamp())
        << "\","
        << "\"count\":"
        << connections.size()
        << ","
        << "\"connections\":[";

    for (std::size_t i = 0; i < connections.size(); ++i) {
        if (i > 0) {
            std::cout << ',';
        }

        std::cout << connection_to_json(
            connections[i]
        );
    }

    std::cout << "]}\n";
}

void display_jsonl(
    const std::vector<Connection>& connections
) {
    const auto current_timestamp = timestamp();

    for (const auto& connection : connections) {
        std::cout
            << "{"
            << "\"timestamp\":\""
            << json_escape(current_timestamp)
            << "\","
            << "\"connection\":"
            << connection_to_json(connection)
            << "}\n";
    }
}

void display_connections(
    const std::vector<Connection>& connections,
    const Options& options
) {
    const bool color =
        !options.no_color &&
        options.format == OutputFormat::TABLE &&
        isatty(STDOUT_FILENO);

    switch (options.format) {
        case OutputFormat::TABLE:
            display_table(connections, color);
            break;
        case OutputFormat::JSON:
            display_json(connections);
            break;
        case OutputFormat::JSONL:
            display_jsonl(connections);
            break;
    }

    std::cout.flush();
}

void sleep_interruptibly(int seconds) {
    constexpr auto step =
        std::chrono::milliseconds(100);

    const auto deadline =
        std::chrono::steady_clock::now() +
        std::chrono::seconds(seconds);

    while (
        running.load(std::memory_order_relaxed) &&
        std::chrono::steady_clock::now() < deadline
    ) {
        const auto remaining =
            deadline - std::chrono::steady_clock::now();

        std::this_thread::sleep_for(
            std::min(
                step,
                std::chrono::duration_cast<
                    std::chrono::milliseconds
                >(remaining)
            )
        );
    }
}

void run(const Options& options) {
    while (running.load(std::memory_order_relaxed)) {
        const auto connections =
            read_connections(options);

        display_connections(
            connections,
            options
        );

        if (options.once) {
            break;
        }

        sleep_interruptibly(options.interval);
    }
}

std::string require_value(
    int argc,
    char* argv[],
    int& index,
    const std::string& option
) {
    if (index + 1 >= argc) {
        throw std::runtime_error(
            "Missing value for " + option
        );
    }

    return argv[++index];
}

int parse_positive_int(
    const std::string& value,
    const std::string& name
) {
    const auto parsed =
        parse_unsigned(value, 10, name);

    if (
        parsed == 0 ||
        parsed >
        static_cast<std::uint64_t>(
            std::numeric_limits<int>::max()
        )
    ) {
        throw std::runtime_error(
            name + " must be a positive integer"
        );
    }

    return static_cast<int>(parsed);
}

std::uint16_t parse_cli_port(
    const std::string& value
) {
    const auto parsed =
        parse_unsigned(value, 10, "port");

    if (
        parsed >
        std::numeric_limits<std::uint16_t>::max()
    ) {
        throw std::runtime_error(
            "Port must be between 0 and 65535"
        );
    }

    return static_cast<std::uint16_t>(parsed);
}

Protocol parse_protocol(std::string value) {
    value = lowercase(std::move(value));

    if (value == "tcp") {
        return Protocol::TCP;
    }

    if (value == "tcp6") {
        return Protocol::TCP6;
    }

    if (value == "all") {
        return Protocol::ALL;
    }

    throw std::runtime_error(
        "Protocol must be tcp, tcp6, or all"
    );
}

OutputFormat parse_format(std::string value) {
    value = lowercase(std::move(value));

    if (value == "table" || value == "text") {
        return OutputFormat::TABLE;
    }

    if (value == "json") {
        return OutputFormat::JSON;
    }

    if (value == "jsonl") {
        return OutputFormat::JSONL;
    }

    throw std::runtime_error(
        "Format must be table, json, or jsonl"
    );
}

void print_help(const char* program) {
    std::cout
        << "Usage: " << program << " [options]\n\n"
        << "Options:\n"
        << "  --once                  Read connections once and exit\n"
        << "  --watch <seconds>       Watch continuously at the given interval\n"
        << "  --interval <seconds>    Alias for --watch\n"
        << "  --protocol <value>      tcp, tcp6, or all\n"
        << "  --state <state>         Filter by TCP state\n"
        << "  --filter-state <state>  Alias for --state\n"
        << "  --ip <address>          Filter by local or peer address\n"
        << "  --filter-ip <address>   Alias for --ip\n"
        << "  --port <port>           Filter by local or peer port\n"
        << "  --filter-port <port>    Alias for --port\n"
        << "  --format <format>       table, json, or jsonl\n"
        << "  --output-format <fmt>   Alias for --format\n"
        << "  --no-color              Disable terminal colors\n"
        << "  --help                   Show this help\n";
}

Options parse_arguments(
    int argc,
    char* argv[]
) {
    Options options;

    for (int i = 1; i < argc; ++i) {
        const std::string argument = argv[i];

        if (
            argument == "--help" ||
            argument == "-h"
        ) {
            print_help(argv[0]);
            std::exit(EXIT_SUCCESS);
        }

        if (argument == "--once") {
            options.once = true;
            continue;
        }

        if (argument == "--no-color") {
            options.no_color = true;
            continue;
        }

        if (
            argument == "--watch" ||
            argument == "--interval"
        ) {
            options.interval = parse_positive_int(
                require_value(
                    argc,
                    argv,
                    i,
                    argument
                ),
                "interval"
            );
            options.once = false;
            continue;
        }

        if (argument == "--protocol") {
            options.protocol = parse_protocol(
                require_value(
                    argc,
                    argv,
                    i,
                    argument
                )
            );
            continue;
        }

        if (
            argument == "--state" ||
            argument == "--filter-state"
        ) {
            auto state = uppercase(
                require_value(
                    argc,
                    argv,
                    i,
                    argument
                )
            );

            if (!valid_tcp_state(state)) {
                throw std::runtime_error(
                    "Unknown TCP state: " + state
                );
            }

            options.filter_state =
                std::move(state);

            continue;
        }

        if (
            argument == "--ip" ||
            argument == "--filter-ip"
        ) {
            options.filter_ip =
                require_value(
                    argc,
                    argv,
                    i,
                    argument
                );
            continue;
        }

        if (
            argument == "--port" ||
            argument == "--filter-port"
        ) {
            options.filter_port =
                parse_cli_port(
                    require_value(
                        argc,
                        argv,
                        i,
                        argument
                    )
                );
            continue;
        }

        if (
            argument == "--format" ||
            argument == "--output-format"
        ) {
            options.format =
                parse_format(
                    require_value(
                        argc,
                        argv,
                        i,
                        argument
                    )
                );
            continue;
        }

        throw std::runtime_error(
            "Unknown option: " + argument
        );
    }

    return options;
}

struct AdvancedOptions {
    bool once = false;
    bool color = true;
    bool resolve_process = false;
    bool changes = false;
    bool summary = false;
    bool show_listening = true;
    bool show_connected = true;
    bool show_udp = true;
    bool show_tcp = true;
    bool show_ipv4 = true;
    bool show_ipv6 = true;
    bool show_header = true;
    bool show_timestamp = true;
    bool include_kernel = false;
    bool strict = false;
    bool delta_only = false;
    bool show_users = false;
    bool show_command = false;
    bool show_process = false;
    bool numeric = true;
    bool unique = false;
    bool reverse = false;
    bool quiet = false;
    bool statistics = false;
    bool show_inodes = true;
    bool show_uid = true;
    bool show_pid = true;
    bool show_errors = false;
    bool show_totals = true;
    bool show_rates = false;
    bool show_histogram = false;
    bool show_protocol_summary = false;
    bool show_state_summary = false;
    bool show_user_summary = false;
    bool show_process_summary = false;
    bool show_port_summary = false;
    bool show_address_summary = false;
    bool show_diff_summary = false;
    bool show_duration = false;
    bool include_loopback = true;
    bool include_unspecified = true;
    bool include_timewait = true;
    bool include_closed = true;
    bool compact = false;
    bool headers_once = false;
    bool no_truncate = false;
    bool pretty_json = false;
    bool sort_numeric = false;
    bool case_sensitive = false;
    bool ignore_permission_errors = true;
    int interval_ms = 2000;
    int count = 0;
    int limit = 0;
    int top = 10;
    int width = 0;
    int min_uid = -1;
    int max_uid = -1;
    int min_pid = -1;
    int max_pid = -1;
    int min_port = -1;
    int max_port = -1;
    int history = 16;
    int max_scan_pids = 100000;
    std::string format = "table";
    std::string sort = "protocol";
    std::string filter_state;
    std::string filter_ip;
    std::string filter_protocol;
    std::string filter_command;
    std::string filter_user;
    std::string filter_local;
    std::string filter_remote;
    std::string filter_family;
    std::string filter_direction;
    std::string filter_process;
    std::string filter_port;
    std::string filter_pid;
    std::string filter_uid;
    std::string filter_inode;
    std::string filter_text;
    std::string output_path;
    std::string proc_root = "/proc";
};

struct AdvancedRecord {
    Connection connection;
    std::string command;
    std::string process_name;
    std::string username;
    std::string family;
    std::string source;
    std::string identity;
    std::string event;
    std::string first_seen;
    std::string last_seen;
    std::vector<int> pids;
    bool valid = true;
    bool appeared = false;
    bool disappeared = false;
    bool changed = false;
    std::uint64_t tx_queue = 0;
    std::uint64_t rx_queue = 0;
    std::uint64_t drops = 0;
    std::uint64_t timer = 0;
    std::uint64_t retransmits = 0;
    std::uint64_t observations = 0;
};

struct AdvancedCounters {
    std::uint64_t scanned_lines = 0;
    std::uint64_t parsed_lines = 0;
    std::uint64_t malformed_lines = 0;
    std::uint64_t filtered_lines = 0;
    std::uint64_t opened_files = 0;
    std::uint64_t missing_files = 0;
    std::uint64_t permission_errors = 0;
    std::uint64_t scanned_processes = 0;
    std::uint64_t scanned_descriptors = 0;
    std::uint64_t matched_descriptors = 0;
    std::uint64_t created = 0;
    std::uint64_t removed = 0;
    std::uint64_t updated = 0;
    std::uint64_t unchanged = 0;
    std::uint64_t snapshots = 0;
    std::uint64_t output_records = 0;
    std::uint64_t output_bytes = 0;
};

struct AdvancedSnapshot {
    std::vector<AdvancedRecord> records;
    AdvancedCounters counters;
    std::string captured_at;
    std::chrono::steady_clock::time_point monotonic_at;
    std::size_t index = 0;
};

struct AdvancedDelta {
    std::vector<AdvancedRecord> created;
    std::vector<AdvancedRecord> removed;
    std::vector<AdvancedRecord> updated;
    std::size_t unchanged = 0;
};

std::string advanced_trim(std::string value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) {
        return {};
    }
    const auto last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

std::string advanced_read_first_line(const std::string& path) {
    std::ifstream input(path);
    std::string result;
    if (input) {
        std::getline(input, result);
    }
    return result;
}

std::string advanced_read_command(const std::string& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        return {};
    }
    std::string result;
    result.resize(4096);
    input.read(result.data(), static_cast<std::streamsize>(result.size()));
    result.resize(static_cast<std::size_t>(input.gcount()));
    for (char& c : result) {
        if (c == '\0') {
            c = ' ';
        }
    }
    return advanced_trim(result);
}

bool advanced_digits(std::string_view value) {
    return !value.empty() && std::all_of(
        value.begin(), value.end(),
        [](unsigned char c) { return c >= '0' && c <= '9'; }
    );
}

std::optional<std::uint64_t> advanced_number(
    std::string_view value,
    int base = 10
) {
    std::uint64_t result = 0;
    const char* begin = value.data();
    const char* end = begin + value.size();
    const auto parsed = std::from_chars(begin, end, result, base);
    if (parsed.ec != std::errc{} || parsed.ptr != end) {
        return std::nullopt;
    }
    return result;
}

std::optional<int> advanced_int(std::string_view value) {
    int result = 0;
    const auto parsed = std::from_chars(
        value.data(), value.data() + value.size(), result
    );
    if (parsed.ec != std::errc{} ||
        parsed.ptr != value.data() + value.size()) {
        return std::nullopt;
    }
    return result;
}

std::vector<std::string> advanced_fields(const std::string& line) {
    std::istringstream stream(line);
    std::vector<std::string> result;
    std::string field;
    while (stream >> field) {
        result.push_back(std::move(field));
    }
    return result;
}

std::string advanced_username(std::uint32_t uid) {
    long buffer_size = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (buffer_size < 1024 || buffer_size > 1048576) {
        buffer_size = 16384;
    }
    std::vector<char> buffer(static_cast<std::size_t>(buffer_size));
    struct passwd pwd{};
    struct passwd* result = nullptr;
    const int status = getpwuid_r(
        static_cast<uid_t>(uid),
        &pwd,
        buffer.data(),
        buffer.size(),
        &result
    );
    if (status != 0 || result == nullptr || pwd.pw_name == nullptr) {
        return std::to_string(uid);
    }
    return pwd.pw_name;
}

std::string advanced_csv_escape(const std::string& value) {
    if (value.find_first_of(",\"\r\n") == std::string::npos) {
        return value;
    }
    std::string result = "\"";
    for (char c : value) {
        if (c == '"') {
            result += "\"\"";
        } else {
            result += c;
        }
    }
    result += '"';
    return result;
}

std::string advanced_json_string(const std::string& value) {
    return "\"" + json_escape(value) + "\"";
}

std::string advanced_identity(const AdvancedRecord& record) {
    const auto& c = record.connection;
    return c.protocol + "|" + c.local_address + "|" +
        std::to_string(c.local_port) + "|" + c.peer_address + "|" +
        std::to_string(c.peer_port) + "|" + std::to_string(c.inode);
}

bool advanced_loopback(const std::string& address) {
    return address == "::1" || address == "127.0.0.1" ||
        address.rfind("127.", 0) == 0;
}

bool advanced_unspecified(const std::string& address) {
    return address == "::" || address == "0.0.0.0";
}

bool advanced_contains(
    const std::string& haystack,
    const std::string& needle,
    bool sensitive
) {
    if (needle.empty()) {
        return true;
    }
    if (sensitive) {
        return haystack.find(needle) != std::string::npos;
    }
    return lowercase(haystack).find(lowercase(needle)) != std::string::npos;
}

std::optional<std::pair<std::string, std::uint16_t>> advanced_endpoint(
    const std::string& value,
    bool ipv6
) {
    const auto position = value.rfind(':');
    if (position == std::string::npos) {
        return std::nullopt;
    }
    const auto port = advanced_number(
        std::string_view(value).substr(position + 1), 16
    );
    if (!port || *port > 65535) {
        return std::nullopt;
    }
    try {
        const auto address = value.substr(0, position);
        return std::make_pair(
            ipv6 ? parse_ipv6(address) : parse_ipv4(address),
            static_cast<std::uint16_t>(*port)
        );
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

std::optional<AdvancedRecord> advanced_parse_socket(
    const std::string& line,
    const std::string& protocol
) {
    const auto fields = advanced_fields(line);
    if (fields.size() < 10) {
        return std::nullopt;
    }
    const bool ipv6 = protocol.find('6') != std::string::npos;
    const bool udp = protocol.rfind("udp", 0) == 0;
    const auto local = advanced_endpoint(fields[1], ipv6);
    const auto remote = advanced_endpoint(fields[2], ipv6);
    const auto uid = advanced_number(fields[7]);
    const auto inode = advanced_number(fields[9]);
    if (!local || !remote || !uid || !inode || *uid > UINT32_MAX) {
        return std::nullopt;
    }
    AdvancedRecord record;
    record.connection.protocol = protocol;
    record.connection.local_address = local->first;
    record.connection.local_port = local->second;
    record.connection.peer_address = remote->first;
    record.connection.peer_port = remote->second;
    record.connection.uid = static_cast<std::uint32_t>(*uid);
    record.connection.inode = *inode;
    record.connection.state = udp ? "UNCONN" : state_from_hex(fields[3]);
    if (udp && fields[3] == "01") {
        record.connection.state = "ESTABLISHED";
    }
    record.family = ipv6 ? "ipv6" : "ipv4";
    record.source = "/proc/net/" + protocol;
    if (fields.size() > 4) {
        const auto queues = split(fields[4], ':');
        if (queues.size() == 2) {
            record.tx_queue = advanced_number(queues[0], 16).value_or(0);
            record.rx_queue = advanced_number(queues[1], 16).value_or(0);
        }
    }
    if (fields.size() > 5) {
        const auto timer_parts = split(fields[5], ':');
        if (!timer_parts.empty()) {
            record.timer = advanced_number(timer_parts[0], 16).value_or(0);
        }
    }
    if (fields.size() > 6) {
        record.retransmits = advanced_number(fields[6], 16).value_or(0);
    }
    if (udp && fields.size() > 12) {
        record.drops = advanced_number(fields.back()).value_or(0);
    }
    record.identity = advanced_identity(record);
    return record;
}

bool advanced_filter(const AdvancedRecord& record, const AdvancedOptions& opt) {
    const auto& c = record.connection;
    if (!opt.show_tcp && c.protocol.rfind("tcp", 0) == 0) return false;
    if (!opt.show_udp && c.protocol.rfind("udp", 0) == 0) return false;
    if (!opt.show_ipv4 && record.family == "ipv4") return false;
    if (!opt.show_ipv6 && record.family == "ipv6") return false;
    if (!opt.show_listening && c.state == "LISTEN") return false;
    if (!opt.show_connected && c.state == "ESTABLISHED") return false;
    if (!opt.include_timewait && c.state == "TIME_WAIT") return false;
    if (!opt.include_closed && c.state == "CLOSE") return false;
    if (!opt.include_loopback &&
        (advanced_loopback(c.local_address) || advanced_loopback(c.peer_address))) return false;
    if (!opt.include_unspecified &&
        (advanced_unspecified(c.local_address) || advanced_unspecified(c.peer_address))) return false;
    if (opt.min_uid >= 0 && c.uid < static_cast<unsigned>(opt.min_uid)) return false;
    if (opt.max_uid >= 0 && c.uid > static_cast<unsigned>(opt.max_uid)) return false;
    if (opt.min_port >= 0 && c.local_port < opt.min_port && c.peer_port < opt.min_port) return false;
    if (opt.max_port >= 0 && c.local_port > opt.max_port && c.peer_port > opt.max_port) return false;
    if (!advanced_contains(c.state, opt.filter_state, opt.case_sensitive)) return false;
    if (!advanced_contains(c.protocol, opt.filter_protocol, opt.case_sensitive)) return false;
    if (!advanced_contains(record.family, opt.filter_family, opt.case_sensitive)) return false;
    if (!opt.filter_ip.empty() &&
        !advanced_contains(c.local_address, opt.filter_ip, opt.case_sensitive) &&
        !advanced_contains(c.peer_address, opt.filter_ip, opt.case_sensitive)) return false;
    if (!advanced_contains(c.local_address, opt.filter_local, opt.case_sensitive)) return false;
    if (!advanced_contains(c.peer_address, opt.filter_remote, opt.case_sensitive)) return false;
    if (!opt.filter_port.empty() &&
        std::to_string(c.local_port) != opt.filter_port &&
        std::to_string(c.peer_port) != opt.filter_port) return false;
    if (!opt.filter_uid.empty() && std::to_string(c.uid) != opt.filter_uid) return false;
    if (!opt.filter_inode.empty() && std::to_string(c.inode) != opt.filter_inode) return false;
    if (!advanced_contains(record.command, opt.filter_command, opt.case_sensitive)) return false;
    if (!advanced_contains(record.process_name, opt.filter_process, opt.case_sensitive)) return false;
    if (!advanced_contains(record.username, opt.filter_user, opt.case_sensitive)) return false;
    if (!opt.filter_pid.empty()) {
        bool found = false;
        for (int pid : record.pids) {
            if (std::to_string(pid) == opt.filter_pid) found = true;
        }
        if (!found) return false;
    }
    if (!opt.filter_text.empty()) {
        const auto haystack = c.protocol + " " + c.state + " " +
            c.local_address + " " + c.peer_address + " " +
            record.command + " " + record.process_name + " " + record.username;
        if (!advanced_contains(haystack, opt.filter_text, opt.case_sensitive)) return false;
    }
    return true;
}

std::unordered_map<std::uint64_t, std::vector<int>> advanced_owners(
    const AdvancedOptions& opt,
    AdvancedCounters& counters
) {
    namespace fs = std::filesystem;
    std::unordered_map<std::uint64_t, std::vector<int>> owners;
    std::error_code ec;
    fs::directory_iterator it(
        opt.proc_root,
        fs::directory_options::skip_permission_denied,
        ec
    );
    fs::directory_iterator end;
    if (ec) {
        ++counters.permission_errors;
        return owners;
    }
    for (; it != end; it.increment(ec)) {
        if (ec) {
            ++counters.permission_errors;
            ec.clear();
            continue;
        }
        const auto name = it->path().filename().string();
        if (!advanced_digits(name)) continue;
        const auto pid_value = advanced_int(name);
        if (!pid_value) continue;
        const int pid = *pid_value;
        if (opt.min_pid >= 0 && pid < opt.min_pid) continue;
        if (opt.max_pid >= 0 && pid > opt.max_pid) continue;
        if (++counters.scanned_processes > static_cast<unsigned>(opt.max_scan_pids)) break;
        const auto fd_path = it->path() / "fd";
        std::error_code fd_error;
        fs::directory_iterator fd_it(
            fd_path,
            fs::directory_options::skip_permission_denied,
            fd_error
        );
        if (fd_error) {
            ++counters.permission_errors;
            continue;
        }
        for (; fd_it != end; fd_it.increment(fd_error)) {
            if (fd_error) {
                ++counters.permission_errors;
                fd_error.clear();
                continue;
            }
            ++counters.scanned_descriptors;
            std::error_code link_error;
            const auto link = fs::read_symlink(fd_it->path(), link_error);
            if (link_error) continue;
            const auto target = link.string();
            if (target.rfind("socket:[", 0) != 0 || target.back() != ']') continue;
            const auto inode = advanced_number(
                std::string_view(target).substr(8, target.size() - 9)
            );
            if (!inode) continue;
            ++counters.matched_descriptors;
            auto& entries = owners[*inode];
            if (std::find(entries.begin(), entries.end(), pid) == entries.end()) {
                entries.push_back(pid);
            }
        }
    }
    for (auto& [inode, pids] : owners) {
        std::sort(pids.begin(), pids.end());
    }
    return owners;
}

void advanced_enrich(
    AdvancedRecord& record,
    const AdvancedOptions& opt,
    const std::unordered_map<std::uint64_t, std::vector<int>>& owners,
    std::unordered_map<int, std::pair<std::string, std::string>>& process_cache,
    std::unordered_map<std::uint32_t, std::string>& user_cache
) {
    const auto uid = record.connection.uid;
    if (opt.show_users || !opt.filter_user.empty() || opt.show_user_summary) {
        const auto found = user_cache.find(uid);
        if (found == user_cache.end()) {
            record.username = advanced_username(uid);
            user_cache.emplace(uid, record.username);
        } else {
            record.username = found->second;
        }
    }
    const auto found = owners.find(record.connection.inode);
    if (found == owners.end()) return;
    record.pids = found->second;
    if (record.pids.empty()) return;
    const int pid = record.pids.front();
    auto process = process_cache.find(pid);
    if (process == process_cache.end()) {
        const auto prefix = opt.proc_root + "/" + std::to_string(pid) + "/";
        const auto name = advanced_trim(advanced_read_first_line(prefix + "comm"));
        const auto command = advanced_read_command(prefix + "cmdline");
        process = process_cache.emplace(pid, std::make_pair(name, command)).first;
    }
    record.process_name = process->second.first;
    record.command = process->second.second;
}

AdvancedSnapshot advanced_capture(const AdvancedOptions& opt) {
    AdvancedSnapshot snapshot;
    snapshot.captured_at = timestamp();
    snapshot.monotonic_at = std::chrono::steady_clock::now();
    std::vector<std::string> protocols;
    if (opt.show_tcp) {
        if (opt.show_ipv4) protocols.emplace_back("tcp");
        if (opt.show_ipv6) protocols.emplace_back("tcp6");
    }
    if (opt.show_udp) {
        if (opt.show_ipv4) protocols.emplace_back("udp");
        if (opt.show_ipv6) protocols.emplace_back("udp6");
    }
    for (const auto& protocol : protocols) {
        std::ifstream file(opt.proc_root + "/net/" + protocol);
        if (!file) {
            ++snapshot.counters.missing_files;
            if (opt.strict) {
                throw std::runtime_error("Cannot open " + opt.proc_root + "/net/" + protocol);
            }
            continue;
        }
        ++snapshot.counters.opened_files;
        std::string line;
        std::getline(file, line);
        while (std::getline(file, line)) {
            ++snapshot.counters.scanned_lines;
            auto parsed = advanced_parse_socket(line, protocol);
            if (!parsed) {
                ++snapshot.counters.malformed_lines;
                continue;
            }
            ++snapshot.counters.parsed_lines;
            snapshot.records.push_back(std::move(*parsed));
        }
    }
    const bool needs_owners = opt.resolve_process || opt.show_process ||
        opt.show_command || !opt.filter_pid.empty() ||
        !opt.filter_process.empty() || !opt.filter_command.empty() ||
        opt.show_process_summary;
    std::unordered_map<std::uint64_t, std::vector<int>> owners;
    if (needs_owners) {
        owners = advanced_owners(opt, snapshot.counters);
    }
    std::unordered_map<int, std::pair<std::string, std::string>> process_cache;
    std::unordered_map<std::uint32_t, std::string> user_cache;
    std::vector<AdvancedRecord> filtered;
    filtered.reserve(snapshot.records.size());
    for (auto& record : snapshot.records) {
        advanced_enrich(record, opt, owners, process_cache, user_cache);
        if (advanced_filter(record, opt)) {
            filtered.push_back(std::move(record));
        } else {
            ++snapshot.counters.filtered_lines;
        }
    }
    snapshot.records = std::move(filtered);
    return snapshot;
}

std::string advanced_pid_list(const AdvancedRecord& record) {
    std::string result;
    for (std::size_t i = 0; i < record.pids.size(); ++i) {
        if (i != 0) result += ',';
        result += std::to_string(record.pids[i]);
    }
    return result;
}

std::string advanced_key(const AdvancedRecord& record) {
    return record.identity;
}

bool advanced_different(const AdvancedRecord& a, const AdvancedRecord& b) {
    return a.connection.state != b.connection.state ||
        a.tx_queue != b.tx_queue || a.rx_queue != b.rx_queue ||
        a.retransmits != b.retransmits || a.drops != b.drops ||
        a.pids != b.pids;
}

AdvancedDelta advanced_compare(
    const AdvancedSnapshot& previous,
    const AdvancedSnapshot& current
) {
    AdvancedDelta result;
    std::unordered_map<std::string, const AdvancedRecord*> old_records;
    std::unordered_map<std::string, const AdvancedRecord*> new_records;
    for (const auto& record : previous.records) {
        old_records[advanced_key(record)] = &record;
    }
    for (const auto& record : current.records) {
        new_records[advanced_key(record)] = &record;
        const auto found = old_records.find(advanced_key(record));
        if (found == old_records.end()) {
            auto created = record;
            created.event = "created";
            created.appeared = true;
            result.created.push_back(std::move(created));
        } else if (advanced_different(*found->second, record)) {
            auto updated = record;
            updated.event = "updated";
            updated.changed = true;
            result.updated.push_back(std::move(updated));
        } else {
            ++result.unchanged;
        }
    }
    for (const auto& record : previous.records) {
        if (new_records.find(advanced_key(record)) == new_records.end()) {
            auto removed = record;
            removed.event = "removed";
            removed.disappeared = true;
            result.removed.push_back(std::move(removed));
        }
    }
    return result;
}

std::vector<AdvancedRecord> advanced_delta_records(const AdvancedDelta& delta) {
    std::vector<AdvancedRecord> result;
    result.reserve(delta.created.size() + delta.removed.size() + delta.updated.size());
    result.insert(result.end(), delta.created.begin(), delta.created.end());
    result.insert(result.end(), delta.removed.begin(), delta.removed.end());
    result.insert(result.end(), delta.updated.begin(), delta.updated.end());
    return result;
}

std::string advanced_sort_field(const AdvancedRecord& record, const std::string& field) {
    const auto& c = record.connection;
    if (field == "state") return c.state;
    if (field == "protocol") return c.protocol;
    if (field == "local") return c.local_address;
    if (field == "remote") return c.peer_address;
    if (field == "user") return record.username;
    if (field == "process") return record.process_name;
    if (field == "command") return record.command;
    if (field == "family") return record.family;
    if (field == "event") return record.event;
    if (field == "uid") return std::to_string(c.uid);
    if (field == "inode") return std::to_string(c.inode);
    if (field == "pid") return advanced_pid_list(record);
    if (field == "local-port") return std::to_string(c.local_port);
    if (field == "remote-port") return std::to_string(c.peer_port);
    if (field == "tx") return std::to_string(record.tx_queue);
    if (field == "rx") return std::to_string(record.rx_queue);
    return c.protocol;
}

std::uint64_t advanced_sort_number(const AdvancedRecord& record, const std::string& field) {
    const auto& c = record.connection;
    if (field == "uid") return c.uid;
    if (field == "inode") return c.inode;
    if (field == "local-port") return c.local_port;
    if (field == "remote-port") return c.peer_port;
    if (field == "tx") return record.tx_queue;
    if (field == "rx") return record.rx_queue;
    if (field == "pid") return record.pids.empty() ? 0 : record.pids.front();
    return 0;
}

bool advanced_numeric_sort_field(const std::string& field) {
    static const std::set<std::string> fields{
        "uid", "inode", "local-port", "remote-port", "tx", "rx", "pid"
    };
    return fields.count(field) != 0;
}

void advanced_sort(std::vector<AdvancedRecord>& records, const AdvancedOptions& opt) {
    const bool numeric = advanced_numeric_sort_field(opt.sort);
    std::stable_sort(records.begin(), records.end(), [&](const auto& a, const auto& b) {
        if (numeric) {
            const auto left = advanced_sort_number(a, opt.sort);
            const auto right = advanced_sort_number(b, opt.sort);
            if (left != right) return opt.reverse ? left > right : left < right;
        } else {
            const auto left = advanced_sort_field(a, opt.sort);
            const auto right = advanced_sort_field(b, opt.sort);
            if (left != right) return opt.reverse ? left > right : left < right;
        }
        return a.identity < b.identity;
    });
    if (opt.unique) {
        std::unordered_set<std::string> seen;
        std::vector<AdvancedRecord> unique_records;
        for (auto& record : records) {
            if (seen.insert(record.identity).second) {
                unique_records.push_back(std::move(record));
            }
        }
        records = std::move(unique_records);
    }
    if (opt.limit > 0 && records.size() > static_cast<unsigned>(opt.limit)) {
        records.resize(static_cast<std::size_t>(opt.limit));
    }
}

std::string advanced_json_record(const AdvancedRecord& record) {
    std::ostringstream out;
    out << '{';
    out << "\"protocol\":" << advanced_json_string(record.connection.protocol) << ',';
    out << "\"family\":" << advanced_json_string(record.family) << ',';
    out << "\"state\":" << advanced_json_string(record.connection.state) << ',';
    out << "\"local_address\":" << advanced_json_string(record.connection.local_address) << ',';
    out << "\"local_port\":" << record.connection.local_port << ',';
    out << "\"peer_address\":" << advanced_json_string(record.connection.peer_address) << ',';
    out << "\"peer_port\":" << record.connection.peer_port << ',';
    out << "\"uid\":" << record.connection.uid << ',';
    out << "\"username\":" << advanced_json_string(record.username) << ',';
    out << "\"inode\":" << record.connection.inode << ',';
    out << "\"process\":" << advanced_json_string(record.process_name) << ',';
    out << "\"command\":" << advanced_json_string(record.command) << ',';
    out << "\"pids\":[";
    for (std::size_t i = 0; i < record.pids.size(); ++i) {
        if (i != 0) out << ',';
        out << record.pids[i];
    }
    out << "],";
    out << "\"tx_queue\":" << record.tx_queue << ',';
    out << "\"rx_queue\":" << record.rx_queue << ',';
    out << "\"timer\":" << record.timer << ',';
    out << "\"retransmits\":" << record.retransmits << ',';
    out << "\"drops\":" << record.drops << ',';
    out << "\"event\":" << advanced_json_string(record.event) << ',';
    out << "\"identity\":" << advanced_json_string(record.identity);
    out << '}';
    return out.str();
}

std::string advanced_short(const std::string& value, std::size_t width) {
    if (value.size() <= width) return value;
    if (width < 4) return value.substr(0, width);
    return value.substr(0, width - 3) + "...";
}

std::string advanced_table(
    const std::vector<AdvancedRecord>& records,
    const AdvancedOptions& opt,
    const std::string& captured_at
) {
    std::ostringstream out;
    if (opt.show_timestamp) out << "Timestamp: " << captured_at << '\n';
    if (opt.show_header) {
        out << std::left
            << std::setw(6) << "NETID"
            << std::setw(14) << "STATE"
            << std::setw(opt.compact ? 27 : 44) << "LOCAL"
            << std::setw(opt.compact ? 27 : 44) << "REMOTE";
        if (opt.show_uid) out << std::setw(9) << "UID";
        if (opt.show_inodes) out << std::setw(13) << "INODE";
        if (opt.show_pid) out << std::setw(12) << "PID";
        if (opt.show_users) out << std::setw(14) << "USER";
        if (opt.show_process) out << std::setw(18) << "PROCESS";
        if (opt.show_command) out << "COMMAND ";
        if (opt.changes) out << " EVENT";
        out << '\n';
    }
    const std::size_t endpoint_width = opt.compact ? 27 : 44;
    for (const auto& record : records) {
        const auto& c = record.connection;
        const auto local = endpoint(c.local_address, c.local_port);
        const auto remote = endpoint(c.peer_address, c.peer_port);
        out << std::left
            << std::setw(6) << c.protocol
            << std::setw(14) << c.state
            << std::setw(endpoint_width) << advanced_short(local, endpoint_width - 1)
            << std::setw(endpoint_width) << advanced_short(remote, endpoint_width - 1);
        if (opt.show_uid) out << std::setw(9) << c.uid;
        if (opt.show_inodes) out << std::setw(13) << c.inode;
        if (opt.show_pid) out << std::setw(12) << advanced_short(advanced_pid_list(record), 11);
        if (opt.show_users) out << std::setw(14) << advanced_short(record.username, 13);
        if (opt.show_process) out << std::setw(18) << advanced_short(record.process_name, 17);
        if (opt.show_command) out << advanced_short(record.command, opt.no_truncate ? 4096 : 64);
        if (opt.changes) out << ' ' << record.event;
        out << '\n';
    }
    if (opt.show_totals) out << "Total: " << records.size() << '\n';
    return out.str();
}

std::string advanced_csv(
    const std::vector<AdvancedRecord>& records,
    const AdvancedOptions& opt
) {
    std::ostringstream out;
    if (opt.show_header) {
        out << "protocol,family,state,local_address,local_port,peer_address,peer_port,";
        out << "uid,username,inode,pids,process,command,tx_queue,rx_queue,";
        out << "retransmits,drops,event\n";
    }
    for (const auto& record : records) {
        const auto& c = record.connection;
        out << advanced_csv_escape(c.protocol) << ',';
        out << advanced_csv_escape(record.family) << ',';
        out << advanced_csv_escape(c.state) << ',';
        out << advanced_csv_escape(c.local_address) << ',';
        out << c.local_port << ',';
        out << advanced_csv_escape(c.peer_address) << ',';
        out << c.peer_port << ',';
        out << c.uid << ',';
        out << advanced_csv_escape(record.username) << ',';
        out << c.inode << ',';
        out << advanced_csv_escape(advanced_pid_list(record)) << ',';
        out << advanced_csv_escape(record.process_name) << ',';
        out << advanced_csv_escape(record.command) << ',';
        out << record.tx_queue << ',';
        out << record.rx_queue << ',';
        out << record.retransmits << ',';
        out << record.drops << ',';
        out << advanced_csv_escape(record.event) << '\n';
    }
    return out.str();
}

std::string advanced_json(
    const std::vector<AdvancedRecord>& records,
    const std::string& captured_at,
    bool jsonl
) {
    std::ostringstream out;
    if (jsonl) {
        for (const auto& record : records) {
            out << "{\"timestamp\":" << advanced_json_string(captured_at);
            out << ",\"connection\":" << advanced_json_record(record) << "}\n";
        }
    } else {
        out << "{\"timestamp\":" << advanced_json_string(captured_at);
        out << ",\"count\":" << records.size() << ",\"connections\":[";
        for (std::size_t i = 0; i < records.size(); ++i) {
            if (i != 0) out << ',';
            out << advanced_json_record(records[i]);
        }
        out << "]}\n";
    }
    return out.str();
}

std::map<std::string, std::size_t> advanced_count_by(
    const std::vector<AdvancedRecord>& records,
    const std::string& field
) {
    std::map<std::string, std::size_t> counts;
    for (const auto& record : records) {
        const auto value = advanced_sort_field(record, field);
        ++counts[value.empty() ? "unknown" : value];
    }
    return counts;
}

std::vector<std::pair<std::string, std::size_t>> advanced_top(
    const std::map<std::string, std::size_t>& counts,
    int limit
) {
    std::vector<std::pair<std::string, std::size_t>> result(
        counts.begin(), counts.end()
    );
    std::sort(result.begin(), result.end(), [](const auto& a, const auto& b) {
        if (a.second != b.second) return a.second > b.second;
        return a.first < b.first;
    });
    if (limit > 0 && result.size() > static_cast<unsigned>(limit)) {
        result.resize(static_cast<std::size_t>(limit));
    }
    return result;
}

std::string advanced_summary_section(
    const std::vector<AdvancedRecord>& records,
    const std::string& field,
    int top
) {
    std::ostringstream out;
    out << "\n" << uppercase(field) << " SUMMARY\n";
    out << std::string(38, '-') << '\n';
    for (const auto& [name, count] : advanced_top(advanced_count_by(records, field), top)) {
        out << std::left << std::setw(28) << advanced_short(name, 27);
        out << std::right << std::setw(10) << count << '\n';
    }
    return out.str();
}

std::string advanced_statistics(
    const AdvancedSnapshot& snapshot,
    const AdvancedOptions& opt,
    const std::optional<AdvancedDelta>& delta
) {
    std::ostringstream out;
    const auto& c = snapshot.counters;
    out << "\nSNAPSHOT STATISTICS\n";
    out << "Captured: " << snapshot.captured_at << '\n';
    out << "Connections: " << snapshot.records.size() << '\n';
    out << "Scanned lines: " << c.scanned_lines << '\n';
    out << "Parsed lines: " << c.parsed_lines << '\n';
    out << "Malformed lines: " << c.malformed_lines << '\n';
    out << "Filtered lines: " << c.filtered_lines << '\n';
    out << "Opened files: " << c.opened_files << '\n';
    out << "Missing files: " << c.missing_files << '\n';
    out << "Scanned processes: " << c.scanned_processes << '\n';
    out << "Scanned descriptors: " << c.scanned_descriptors << '\n';
    out << "Matched descriptors: " << c.matched_descriptors << '\n';
    out << "Permission errors: " << c.permission_errors << '\n';
    if (delta) {
        out << "Created: " << delta->created.size() << '\n';
        out << "Removed: " << delta->removed.size() << '\n';
        out << "Updated: " << delta->updated.size() << '\n';
        out << "Unchanged: " << delta->unchanged << '\n';
    }
    if (opt.show_protocol_summary) out << advanced_summary_section(snapshot.records, "protocol", opt.top);
    if (opt.show_state_summary) out << advanced_summary_section(snapshot.records, "state", opt.top);
    if (opt.show_user_summary) out << advanced_summary_section(snapshot.records, "user", opt.top);
    if (opt.show_process_summary) out << advanced_summary_section(snapshot.records, "process", opt.top);
    if (opt.show_address_summary) out << advanced_summary_section(snapshot.records, "remote", opt.top);
    if (opt.show_port_summary) out << advanced_summary_section(snapshot.records, "local-port", opt.top);
    return out.str();
}

std::string advanced_render(
    const std::vector<AdvancedRecord>& records,
    const AdvancedSnapshot& snapshot,
    const AdvancedOptions& opt,
    const std::optional<AdvancedDelta>& delta
) {
    std::string result;
    if (!opt.quiet) {
        if (opt.format == "json") {
            result = advanced_json(records, snapshot.captured_at, false);
        } else if (opt.format == "jsonl") {
            result = advanced_json(records, snapshot.captured_at, true);
        } else if (opt.format == "csv") {
            result = advanced_csv(records, opt);
        } else {
            result = advanced_table(records, opt, snapshot.captured_at);
        }
    }
    if ((opt.statistics || opt.summary) && opt.format == "table") {
        result += advanced_statistics(snapshot, opt, delta);
    }
    return result;
}

void advanced_help(const char* program) {
    std::cout << "Usage: " << program << " --advanced [options]\n\n";
    std::cout << "Monitoring:\n";
    std::cout << "  --once                     Capture one snapshot\n";
    std::cout << "  --watch MS                 Capture repeatedly every MS milliseconds\n";
    std::cout << "  --count N                  Stop after N snapshots\n";
    std::cout << "  --changes                  Show connection lifecycle changes\n";
    std::cout << "  --delta-only               Suppress first full snapshot\n";
    std::cout << "  --process                  Resolve owning PIDs and process names\n";
    std::cout << "  --command                  Include process command lines\n";
    std::cout << "  --users                    Resolve usernames\n";
    std::cout << "  --tcp-only                 Exclude UDP\n";
    std::cout << "  --udp-only                 Exclude TCP\n";
    std::cout << "  --ipv4-only                Exclude IPv6\n";
    std::cout << "  --ipv6-only                Exclude IPv4\n";
    std::cout << "  --no-listen                Exclude listening sockets\n";
    std::cout << "  --no-established           Exclude established sockets\n";
    std::cout << "  --no-loopback              Exclude loopback sockets\n";
    std::cout << "  --no-unspecified           Exclude wildcard endpoints\n";
    std::cout << "  --no-timewait              Exclude TIME_WAIT\n";
    std::cout << "  --no-closed                Exclude CLOSE\n";
    std::cout << "Filtering:\n";
    std::cout << "  --state TEXT               Match socket state\n";
    std::cout << "  --ip TEXT                  Match local or remote IP\n";
    std::cout << "  --local TEXT               Match local IP\n";
    std::cout << "  --remote TEXT              Match remote IP\n";
    std::cout << "  --port N                   Match local or remote port\n";
    std::cout << "  --protocol TEXT            Match protocol\n";
    std::cout << "  --family TEXT              Match address family\n";
    std::cout << "  --pid N                    Match owning PID\n";
    std::cout << "  --uid N                    Match socket UID\n";
    std::cout << "  --inode N                  Match socket inode\n";
    std::cout << "  --user TEXT                Match username\n";
    std::cout << "  --process-name TEXT        Match process name\n";
    std::cout << "  --command-filter TEXT      Match command line\n";
    std::cout << "  --text TEXT                Search multiple fields\n";
    std::cout << "  --min-port N               Lower port bound\n";
    std::cout << "  --max-port N               Upper port bound\n";
    std::cout << "  --min-uid N                Lower UID bound\n";
    std::cout << "  --max-uid N                Upper UID bound\n";
    std::cout << "  --min-pid N                Lower PID bound\n";
    std::cout << "  --max-pid N                Upper PID bound\n";
    std::cout << "  --case-sensitive           Enable case-sensitive substring filters\n";
    std::cout << "Output:\n";
    std::cout << "  --format table|json|jsonl|csv\n";
    std::cout << "  --output PATH              Write output to file\n";
    std::cout << "  --sort FIELD               Sort by state, protocol, local, remote,\n";
    std::cout << "                             uid, inode, pid, local-port, remote-port,\n";
    std::cout << "                             tx, rx, user, process, command, family\n";
    std::cout << "  --reverse                  Reverse sort order\n";
    std::cout << "  --limit N                  Limit rows per snapshot\n";
    std::cout << "  --top N                    Limit summary categories\n";
    std::cout << "  --compact                  Narrow table columns\n";
    std::cout << "  --no-header                Suppress table/CSV header\n";
    std::cout << "  --no-timestamp             Suppress table timestamp\n";
    std::cout << "  --no-totals                Suppress table total\n";
    std::cout << "  --no-uid                   Hide UID column\n";
    std::cout << "  --no-inode                 Hide inode column\n";
    std::cout << "  --no-pid                   Hide PID column\n";
    std::cout << "  --unique                   Deduplicate by socket identity\n";
    std::cout << "  --statistics               Show capture diagnostics\n";
    std::cout << "  --summary                  Show summary diagnostics\n";
    std::cout << "  --summary-protocol         Show protocol counts\n";
    std::cout << "  --summary-state            Show state counts\n";
    std::cout << "  --summary-user             Show username counts\n";
    std::cout << "  --summary-process          Show process counts\n";
    std::cout << "  --summary-address          Show remote address counts\n";
    std::cout << "  --summary-port             Show local port counts\n";
    std::cout << "  --strict                   Fail on unavailable socket tables\n";
    std::cout << "  --proc-root PATH           Alternative procfs root for tests\n";
    std::cout << "  --max-scan-pids N          Cap process scans\n";
    std::cout << "  --help                     Show this help\n";
}

int advanced_required_int(const std::string& value, const std::string& name) {
    const auto parsed = advanced_int(value);
    if (!parsed || *parsed < 0) {
        throw std::runtime_error("Invalid nonnegative " + name + ": " + value);
    }
    return *parsed;
}

AdvancedOptions advanced_parse(int argc, char* argv[]) {
    AdvancedOptions opt;
    opt.once = true;
    for (int i = 1; i < argc; ++i) {
        const std::string argument = argv[i];
        if (argument == "--advanced") continue;
        if (argument == "--help" || argument == "-h") {
            advanced_help(argv[0]);
            std::exit(EXIT_SUCCESS);
        }
        if (argument == "--once") { opt.once = true; continue; }
        if (argument == "--changes") { opt.changes = true; opt.once = false; continue; }
        if (argument == "--delta-only") { opt.delta_only = true; opt.changes = true; opt.once = false; continue; }
        if (argument == "--process") { opt.resolve_process = true; opt.show_process = true; continue; }
        if (argument == "--command") { opt.resolve_process = true; opt.show_command = true; continue; }
        if (argument == "--users") { opt.show_users = true; continue; }
        if (argument == "--tcp-only") { opt.show_udp = false; continue; }
        if (argument == "--udp-only") { opt.show_tcp = false; continue; }
        if (argument == "--ipv4-only") { opt.show_ipv6 = false; continue; }
        if (argument == "--ipv6-only") { opt.show_ipv4 = false; continue; }
        if (argument == "--no-listen") { opt.show_listening = false; continue; }
        if (argument == "--no-established") { opt.show_connected = false; continue; }
        if (argument == "--no-loopback") { opt.include_loopback = false; continue; }
        if (argument == "--no-unspecified") { opt.include_unspecified = false; continue; }
        if (argument == "--no-timewait") { opt.include_timewait = false; continue; }
        if (argument == "--no-closed") { opt.include_closed = false; continue; }
        if (argument == "--case-sensitive") { opt.case_sensitive = true; continue; }
        if (argument == "--reverse") { opt.reverse = true; continue; }
        if (argument == "--compact") { opt.compact = true; continue; }
        if (argument == "--no-header") { opt.show_header = false; continue; }
        if (argument == "--no-timestamp") { opt.show_timestamp = false; continue; }
        if (argument == "--no-totals") { opt.show_totals = false; continue; }
        if (argument == "--no-uid") { opt.show_uid = false; continue; }
        if (argument == "--no-inode") { opt.show_inodes = false; continue; }
        if (argument == "--no-pid") { opt.show_pid = false; continue; }
        if (argument == "--unique") { opt.unique = true; continue; }
        if (argument == "--statistics") { opt.statistics = true; continue; }
        if (argument == "--summary") { opt.summary = true; continue; }
        if (argument == "--summary-protocol") { opt.show_protocol_summary = true; opt.statistics = true; continue; }
        if (argument == "--summary-state") { opt.show_state_summary = true; opt.statistics = true; continue; }
        if (argument == "--summary-user") { opt.show_user_summary = true; opt.statistics = true; continue; }
        if (argument == "--summary-process") { opt.show_process_summary = true; opt.statistics = true; continue; }
        if (argument == "--summary-address") { opt.show_address_summary = true; opt.statistics = true; continue; }
        if (argument == "--summary-port") { opt.show_port_summary = true; opt.statistics = true; continue; }
        if (argument == "--strict") { opt.strict = true; continue; }
        const auto value = require_value(argc, argv, i, argument);
        if (argument == "--watch") {
            opt.interval_ms = advanced_required_int(value, "watch");
            if (opt.interval_ms < 100) throw std::runtime_error("--watch must be at least 100 ms");
            opt.once = false;
        } else if (argument == "--count") {
            opt.count = advanced_required_int(value, "count");
        } else if (argument == "--limit") {
            opt.limit = advanced_required_int(value, "limit");
        } else if (argument == "--top") {
            opt.top = advanced_required_int(value, "top");
        } else if (argument == "--max-scan-pids") {
            opt.max_scan_pids = advanced_required_int(value, "max-scan-pids");
        } else if (argument == "--min-port") {
            opt.min_port = advanced_required_int(value, "min-port");
        } else if (argument == "--max-port") {
            opt.max_port = advanced_required_int(value, "max-port");
        } else if (argument == "--min-uid") {
            opt.min_uid = advanced_required_int(value, "min-uid");
        } else if (argument == "--max-uid") {
            opt.max_uid = advanced_required_int(value, "max-uid");
        } else if (argument == "--min-pid") {
            opt.min_pid = advanced_required_int(value, "min-pid");
        } else if (argument == "--max-pid") {
            opt.max_pid = advanced_required_int(value, "max-pid");
        } else if (argument == "--state") {
            opt.filter_state = value;
        } else if (argument == "--ip") {
            opt.filter_ip = value;
        } else if (argument == "--local") {
            opt.filter_local = value;
        } else if (argument == "--remote") {
            opt.filter_remote = value;
        } else if (argument == "--port") {
            opt.filter_port = std::to_string(advanced_required_int(value, "port"));
        } else if (argument == "--protocol") {
            opt.filter_protocol = value;
        } else if (argument == "--family") {
            opt.filter_family = value;
        } else if (argument == "--pid") {
            opt.filter_pid = std::to_string(advanced_required_int(value, "pid"));
        } else if (argument == "--uid") {
            opt.filter_uid = std::to_string(advanced_required_int(value, "uid"));
        } else if (argument == "--inode") {
            opt.filter_inode = std::to_string(advanced_required_int(value, "inode"));
        } else if (argument == "--user") {
            opt.filter_user = value;
        } else if (argument == "--process-name") {
            opt.filter_process = value;
        } else if (argument == "--command-filter") {
            opt.filter_command = value;
        } else if (argument == "--text") {
            opt.filter_text = value;
        } else if (argument == "--sort") {
            opt.sort = value;
        } else if (argument == "--format") {
            opt.format = value;
        } else if (argument == "--output") {
            opt.output_path = value;
        } else if (argument == "--proc-root") {
            opt.proc_root = value;
        } else {
            throw std::runtime_error("Unknown advanced option: " + argument);
        }
    }
    if (opt.format != "table" && opt.format != "json" &&
        opt.format != "jsonl" && opt.format != "csv") {
        throw std::runtime_error("Invalid output format: " + opt.format);
    }
    if (opt.changes && opt.once) {
        throw std::runtime_error("--changes requires --watch or --count with --watch");
    }
    if (opt.min_port > 65535 || opt.max_port > 65535) {
        throw std::runtime_error("Port bounds must be <= 65535");
    }
    if (opt.min_port >= 0 && opt.max_port >= 0 && opt.min_port > opt.max_port) {
        throw std::runtime_error("Invalid port range");
    }
    if (!opt.filter_user.empty() || opt.show_user_summary) opt.show_users = true;
    if (!opt.filter_process.empty() || !opt.filter_command.empty() ||
        !opt.filter_pid.empty() || opt.show_process_summary) opt.resolve_process = true;
    return opt;
}

void advanced_sleep(int milliseconds) {
    const auto deadline = std::chrono::steady_clock::now() +
        std::chrono::milliseconds(milliseconds);
    while (running.load(std::memory_order_relaxed)) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) break;
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
        std::this_thread::sleep_for(std::min(remaining, std::chrono::milliseconds(100)));
    }
}

int advanced_main(int argc, char* argv[]) {
    auto opt = advanced_parse(argc, argv);
    std::ofstream output_file;
    std::ostream* output = &std::cout;
    if (!opt.output_path.empty()) {
        output_file.open(opt.output_path, std::ios::out | std::ios::trunc);
        if (!output_file) {
            throw std::runtime_error("Cannot open output: " + opt.output_path);
        }
        output = &output_file;
    }
    std::optional<AdvancedSnapshot> previous;
    int iterations = 0;
    while (running.load(std::memory_order_relaxed)) {
        auto snapshot = advanced_capture(opt);
        std::optional<AdvancedDelta> delta;
        std::vector<AdvancedRecord> records;
        if (opt.changes && previous) {
            delta = advanced_compare(*previous, snapshot);
            records = advanced_delta_records(*delta);
        } else if (!opt.delta_only) {
            records = snapshot.records;
        }
        advanced_sort(records, opt);
        *output << advanced_render(records, snapshot, opt, delta);
        output->flush();
        previous = std::move(snapshot);
        ++iterations;
        if (opt.once || (opt.count > 0 && iterations >= opt.count)) break;
        advanced_sleep(opt.interval_ms);
    }
    return EXIT_SUCCESS;
}

}

int main(int argc, char* argv[]) {
#ifndef __linux__
    std::cerr
        << "Error: this program requires Linux.\n";
    return EXIT_FAILURE;
#else
    try {
        std::signal(SIGINT, signal_handler);
        std::signal(SIGTERM, signal_handler);

        for (int i = 1; i < argc; ++i) {
            if (std::string_view(argv[i]) == "--advanced") {
                return advanced_main(argc, argv);
            }
        }
        const auto options =
            parse_arguments(argc, argv);

        run(options);

        return EXIT_SUCCESS;
    } catch (const std::exception& error) {
        std::cerr
            << "Error: "
            << error.what()
            << '\n'
            << "Run with --help for usage information.\n";

        return EXIT_FAILURE;
    }
#endif
}
