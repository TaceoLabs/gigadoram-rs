#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>

#include "doram/bristol_fashion_array.h"

namespace {

constexpr std::size_t kRoundKeys = 10;

using U128 = unsigned __int128;

U128 make_u128(std::uint64_t hi, std::uint64_t lo) {
    return (static_cast<U128>(hi) << 64) | lo;
}

std::string hex_u128(U128 value) {
    std::ostringstream out;
    out << "0x";
    for (int nibble = 31; nibble >= 0; --nibble) {
        out << std::hex << static_cast<unsigned>((value >> (4 * nibble)) & 0xf);
    }
    return out.str();
}

U128 block_to_u128(const emp::block& block) {
    std::uint64_t words[2];
    std::memcpy(words, &block, sizeof(words));
    return make_u128(words[1], words[0]);
}

void initialize_resource_set(int base_port) {
    using namespace emp;

    NUM_THREADS = 1;
    prev_prgs = new PRG*[NUM_THREADS];
    next_prgs = new PRG*[NUM_THREADS];
    private_prgs = new PRG*[NUM_THREADS];
    shared_prgs = new PRG*[NUM_THREADS];
    prev_ios = new RepNetIO*[NUM_THREADS];
    next_ios = new RepNetIO*[NUM_THREADS];
    rep_execs = new SHRepArray*[NUM_THREADS];

    if (party == 1) {
        next_ios[0] = new RepNetIO(nullptr, base_port, true);
        prev_ios[0] = new RepNetIO(nullptr, base_port + 2, true);
    } else if (party == 2) {
        prev_ios[0] = new RepNetIO("127.0.0.1", base_port, true);
        next_ios[0] = new RepNetIO(nullptr, base_port + 1, true);
    } else {
        next_ios[0] = new RepNetIO("127.0.0.1", base_port + 2, true);
        prev_ios[0] = new RepNetIO("127.0.0.1", base_port + 1, true);
    }

    emp::block next_key = makeBlock(0x4c4f574d435f4400ULL + party, 1);
    next_prgs[0] = new PRG(&next_key);
    next_ios[0]->send_block(&next_key, 1);
    next_ios[0]->flush();

    emp::block prev_key;
    prev_ios[0]->recv_block(&prev_key, 1);
    prev_prgs[0] = new PRG(&prev_key);

    emp::block private_key = makeBlock(0x5052495641544500ULL + party, 1);
    emp::block shared_key = makeBlock(0x5348415245440000ULL, 1);
    private_prgs[0] = new PRG(&private_key);
    shared_prgs[0] = new PRG(&shared_key);

    rep_execs[0] = new SHRepArray(0);

    thread_unsafe::prev_prg = prev_prgs[0];
    thread_unsafe::next_prg = next_prgs[0];
    thread_unsafe::private_prg = private_prgs[0];
    thread_unsafe::shared_prg = shared_prgs[0];
    thread_unsafe::prev_io = prev_ios[0];
    thread_unsafe::next_io = next_ios[0];
    thread_unsafe::rep_exec = rep_execs[0];
}

void write_fixture(
    const std::array<emp::block, kRoundKeys>& key,
    const emp::block& input,
    const emp::block& output
) {
    std::cout << "{\n";
    std::cout << "  \"source\": \"BristolFashion_array::compute + circuits/LowMC_reuse_wires.txt\",\n";
    std::cout << "  \"expanded_key\": [\n";
    for (std::size_t i = 0; i < key.size(); ++i) {
        std::cout << "    \"" << hex_u128(block_to_u128(key[i])) << "\"";
        std::cout << (i + 1 == key.size() ? "\n" : ",\n");
    }
    std::cout << "  ],\n";
    std::cout << "  \"input\": \"" << hex_u128(block_to_u128(input)) << "\",\n";
    std::cout << "  \"output\": \"" << hex_u128(block_to_u128(output)) << "\"\n";
    std::cout << "}\n";
}

} // namespace

int main(int argc, char** argv) {
    if (argc != 4) {
        std::cerr << "usage: generate_fixture PARTY BASE_PORT <LowMC_reuse_wires.txt>\n";
        return 1;
    }

    emp::party = std::atoi(argv[1]);
    if (emp::party < 1 || emp::party > 3) {
        std::cerr << "PARTY must be 1, 2, or 3\n";
        return 1;
    }

    const int base_port = std::atoi(argv[2]);
    const std::string circuit_path(argv[3]);
    initialize_resource_set(base_port);

    emp::BristolFashion_array circuit(circuit_path);

    std::array<emp::block, kRoundKeys> key{};
    emp::block input_blocks[kRoundKeys + 1];
    for (std::size_t i = 0; i < key.size(); ++i) {
        key[i] = emp::makeBlock(0x4f485441424c4500ULL, static_cast<std::uint64_t>(i + 1));
        input_blocks[i] = key[i];
    }

    const emp::block input = emp::makeBlock(0x0123456789abcdefULL, 0xfedcba9876543210ULL);
    input_blocks[kRoundKeys] = input;

    emp::rep_array_unsliced<emp::block> circuit_input(kRoundKeys + 1);
    emp::rep_array_unsliced<emp::block> circuit_output(1);
    circuit_input.input_public(input_blocks);
    circuit.compute(circuit_output, circuit_input, 1, emp::thread_unsafe::rep_exec);

    emp::block output;
    circuit_output.reveal_to_all(&output);

    if (emp::party == 1) {
        write_fixture(key, input, output);
    }

    circuit_input.destroy();
    circuit_output.destroy();
    return 0;
}
