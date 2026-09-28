#include <algorithm>
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
