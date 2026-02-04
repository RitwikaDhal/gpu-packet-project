#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <chrono>
#include <pcap.h>
#include <iostream>
#include <vector>
#include <cuda_runtime.h>

#define THREADS_PER_BLOCK 256
#define PACKETS_PER_THREAD 10
#define HASH_SIZE 8

// SHA256 utility macros
#define sig0(x) (rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3))
#define sig1(x) (rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10))
#define rotr(x, a) ((x >> a) | (x << (32 - a)))
#define shr(x, b) (x >> b)
#define SIG0(x) (rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22))
#define SIG1(x) (rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25))
#define Ch(x, y, z) ((x & y) ^ (~x & z))
#define Maj(x, y, z) ((x & y) ^ (x & z) ^ (y & z))

// using time_point = std::chrono::high_resolution_clock::time_point;
// time_point get_time() { 
//     return std::chrono::high_resolution_clock::now(); 
//     }
// double time_diff_seconds(time_point start, time_point end) { 
//     return std::chrono::duration<double>(end - start).count(); 
//     }

__device__ static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

__device__ uint16_t compute_checksum(const unsigned char *addr, int len){
    uint32_t sum = 0;

    // Process 16-bit words
    for (int i = 0; i < len - 1; i += 2)
    {
        uint16_t word = (addr[i] << 8) | addr[i + 1];
        sum += word;
    }

    // If there's an odd byte left
    if (len % 2 == 1)
    {
        uint16_t last_byte = addr[len - 1] << 8; // Big-endian padding
        sum += last_byte;
    }

    // Fold 32-bit sum to 16 bits
    while (sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~((uint16_t)sum);
}


__device__ void calculateHashFromMemory(const unsigned char *data, size_t length, uint32_t output[8]) {
    uint32_t H[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

    size_t paddedLength = ((length + 63) / 64) * 64;
    if (paddedLength > 128) return;
    unsigned char padded[128] = {0};
    memcpy(padded, data, length);
    padded[length] = 0x80;
    uint64_t bit_len = length * 8;
    for (int i = 0; i < 8; i++)
        padded[paddedLength - 1 - i] = (bit_len >> (8 * i)) & 0xFF;

    for (size_t index = 0; index < paddedLength; index += 64) {
        uint32_t W[64];
        for (int i = 0; i < 16; ++i)
            W[i] = (padded[index + (i * 4)] << 24) | (padded[index + (i * 4 + 1)] << 16) |
                   (padded[index + (i * 4 + 2)] << 8) | (padded[index + (i * 4 + 3)]);
        for (int i = 16; i < 64; ++i)
            W[i] = sig1(W[i - 2]) + W[i - 7] + sig0(W[i - 15]) + W[i - 16];

        uint32_t a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
        for (int i = 0; i < 64; ++i) {
            uint32_t T1 = h + SIG1(e) + Ch(e, f, g) + K[i] + W[i];
            uint32_t T2 = SIG0(a) + Maj(a, b, c);
            h = g; g = f; f = e; e = d + T1;
            d = c; c = b; b = a; a = T1 + T2;
        }
        H[0] += a; H[1] += b; H[2] += c; H[3] += d;
        H[4] += e; H[5] += f; H[6] += g; H[7] += h;
    }
    memcpy(output, H, sizeof(H));
}



//using for loops for headder expansion as cuda doesnt have acess to memcpy()
//especially for device-side memory, so using for loop to manually copy data byte by byte.
__global__ void expandAndHashKernel(
    const unsigned char *d_ip_headers, // input: 20B
    unsigned char *d_expanded_headers, // output: 120B
    uint32_t *d_hashes, // output: 256-bit hash for each packet
    int num_packets  // total number of packets
) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x; //calculates the unique thread ID 
    int start_idx = idx * PACKETS_PER_THREAD; //This tells the thread where to start its work
    const char *key = "thisisaverysecure64bytehmacauthenticationkey12345678901234567890"; //static key

    for (int i = 0; i < PACKETS_PER_THREAD; ++i) { // walks through each of our 10 assigned packets.
        int pkt_id = start_idx + i; //calculates the global packet index we are working on, based on:
                                    //start_idx: where our batch of packets begins
                                    //i: which of the 10 packets we on from 0 to 9
        if (pkt_id >= num_packets) return; //safety check —if we’re near the end of all packets and there are fewer than 10 left

        const unsigned char *in = &d_ip_headers[pkt_id * 20]; //Grab the original 20-byte IPv4 header from the input.

        unsigned char *out = &d_expanded_headers[pkt_id * 120]; //This is where you’ll write the expanded version of the header.

        //Copy the original 20B header
        for (int j = 0; j < 20; ++j) out[j] = in[j];

        //Modify and expand the header
        out[0] = (out[0] & 0xF0) | 0x0E;
        out[20] = 0x82; out[21] = 34;
        for (int j = 22; j < 54; ++j) out[j] = 0x00; //Clear space for hash
        out[54] = 0x00; out[55] = 0x00;
        for (int j = 0; j < 64; ++j) out[56 + j] = key[j]; //Add the HMAC key at the end

        //Compute SHA-256 of the whole 120B expanded header
        uint32_t local_hash[HASH_SIZE];
        calculateHashFromMemory(out, 120, local_hash);

        // Embed hash directly into header
        // SHA-256 hash - 32 bytes long.
        // stored inlocal_hash[0] to [7], each number is 4 bytes.
        // This loop:
        // Goes through each of those 8 numbers
        // Breaks each number into 4 bytes
        // Stores all the bytes one after the other into the packet’s header
        // Starts putting them from position out[22] — which is the part of the header reserved for the hash
        for (int j = 0; j < HASH_SIZE; ++j) {
            out[22 + j * 4 + 0] = (local_hash[j] >> 24) & 0xFF;
            out[22 + j * 4 + 1] = (local_hash[j] >> 16) & 0xFF;
            out[22 + j * 4 + 2] = (local_hash[j] >> 8)  & 0xFF;
            out[22 + j * 4 + 3] =  local_hash[j]        & 0xFF;
        }
        // Add checksum calculation after hash insertion
        out[10] = 0;
        out[11] = 0;
        uint16_t checksum = compute_checksum(out, 120);
        out[10] = (checksum >> 8) & 0xFF;
        out[11] = checksum & 0xFF;
        //copying the computed SHA-256 hash from local_hash (a local array in GPU thread memory) 
        //into a global output buffer d_hashes 
        //that will be sent back to the host (CPU) later.
        for (int j = 0; j < HASH_SIZE; j++)
            d_hashes[pkt_id * HASH_SIZE + j] = local_hash[j]; 
            
    }
}

using time_point = std::chrono::high_resolution_clock::time_point;
time_point get_time() { 
    return std::chrono::high_resolution_clock::now(); 
    }
double time_diff_seconds(time_point start, time_point end) { 
    return std::chrono::duration<double>(end - start).count(); 
    }

int main() {
    time_point start_total = get_time();
    time_point start_gpu, end_gpu, start_kernel, end_kernel, start_write, end_write;
    float kernel_ms = 0.0f;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline("tenMillion.pcap", errbuf);
    if (!handle) {
        std::cerr << "Error opening pcap file: " << errbuf << std::endl;
        return 1;
    }

    std::vector<std::vector<unsigned char>> packets;
    std::vector<pcap_pkthdr> pkt_headers;

    const unsigned char *packet;
    struct pcap_pkthdr *header;
    int packet_count = 0;

    time_point read_start = get_time();
    while (pcap_next_ex(handle, &header, &packet) > 0) {
        if (header->caplen < 14 + 20) continue;
        const unsigned char *ip_header = packet + 14;

        std::vector<unsigned char> original_header(ip_header, ip_header + 20);
        packets.push_back(original_header);
        pkt_headers.push_back(*header);
        packet_count++;
    }
    time_point read_end = get_time();

    pcap_close(handle);

    std::vector<unsigned char> flat_input(packet_count * 20);
    for (int i = 0; i < packet_count; ++i)
        memcpy(flat_input.data() + i * 20, packets[i].data(), 20);

    unsigned char *d_ip_headers, *d_expanded_headers;
    uint32_t *d_hashes;

    cudaMalloc(&d_ip_headers, flat_input.size());
    cudaMalloc(&d_expanded_headers, packet_count * 120);
    cudaMalloc(&d_hashes, packet_count * HASH_SIZE * sizeof(uint32_t));

    cudaMemcpy(d_ip_headers, flat_input.data(), flat_input.size(), cudaMemcpyHostToDevice);

    int totalThreads = (packet_count + PACKETS_PER_THREAD - 1) / PACKETS_PER_THREAD;
    int numBlocks = (totalThreads + THREADS_PER_BLOCK - 1) / THREADS_PER_BLOCK;

    cudaEvent_t start_event, stop_event;
    cudaEventCreate(&start_event);
    cudaEventCreate(&stop_event);

    start_gpu = get_time();
    cudaEventRecord(start_event);

    expandAndHashKernel<<<numBlocks, THREADS_PER_BLOCK>>>(d_ip_headers, d_expanded_headers, d_hashes, packet_count);

    cudaEventRecord(stop_event);
    cudaEventSynchronize(stop_event);
    end_gpu = get_time();
    cudaEventElapsedTime(&kernel_ms, start_event, stop_event);

    std::vector<unsigned char> h_expanded(packet_count * 120);
    cudaMemcpy(h_expanded.data(), d_expanded_headers, h_expanded.size(), cudaMemcpyDeviceToHost);

    cudaFree(d_ip_headers);
    cudaFree(d_expanded_headers);
    cudaFree(d_hashes);
    cudaEventDestroy(start_event);
    cudaEventDestroy(stop_event);

    std::vector<std::vector<unsigned char>> final_packets;
    for (int i = 0; i < packet_count; ++i) {
        const unsigned char *exp_hdr = &h_expanded[i * 120];

        std::vector<unsigned char> new_pkt;
        new_pkt.insert(new_pkt.end(), packet, packet + 14);
        new_pkt.insert(new_pkt.end(), exp_hdr, exp_hdr + 120);

        size_t payload_offset = 14 + 20;
        size_t payload_length = pkt_headers[i].caplen > payload_offset ? pkt_headers[i].caplen - payload_offset : 0;
        new_pkt.insert(new_pkt.end(), packet + payload_offset, packet + payload_offset + payload_length);

        final_packets.push_back(new_pkt);
    }

    start_write = get_time();
    pcap_t *pcap = pcap_open_dead(DLT_EN10MB, 65535);
    pcap_dumper_t *dumper = pcap_dump_open(pcap, "modified_expanded.pcap");
    if (!dumper) {
        std::cerr << "Failed to open output file.\n";
        return 1;
    }

    for (int i = 0; i < packet_count; ++i)
        pcap_dump((u_char *)dumper, &pkt_headers[i], final_packets[i].data());

    pcap_dump_close(dumper);
    pcap_close(pcap);
    end_write = get_time();

    double total_time = time_diff_seconds(start_total, get_time());
    double gpu_time = time_diff_seconds(start_gpu, end_gpu);
    double write_time = time_diff_seconds(start_write, end_write);
    double latency_per_packet = total_time / packet_count;
    double throughput_packets_per_second = packet_count / total_time;
    double kernel_per_packet = (kernel_ms / 1000.0) / packet_count;
    double write_per_packet = write_time / packet_count;
    double gpu_per_packet = gpu_time / packet_count;

// Print out performance metrics after processing all packets

std::cout << "\n===== PERFORMANCE METRICS =====" << std::endl;
std::cout << "Packets processed: " << packet_count << std::endl;
std::cout << "Total runtime: " << total_time << " sec" << std::endl;

std::cout << "\n===== TIME BREAKDOWN =====" << std::endl;
std::cout << "GPU total time (copy + kernel): " << gpu_time << " sec (" 
          << (gpu_time / total_time * 100) << "%)" << std::endl;
std::cout << "  - Kernel time (expand + SHA256 hash + checksum): " 
          << kernel_ms / 1000.0 << " sec" << std::endl;
std::cout << "PCAP file writing time: " << write_time << " sec (" 
          << (write_time / total_time * 100) << "%)" << std::endl;

std::cout << "\n===== PER-PACKET TIMINGS =====" << std::endl;
std::cout << "Avg GPU total time per packet: " << gpu_per_packet * 1e6 << " us" << std::endl;
std::cout << "Avg kernel time per packet: " << kernel_per_packet * 1e6 << " us" << std::endl;
std::cout << "Avg writing time per packet: " << write_per_packet * 1e6 << " us" << std::endl;

std::cout << "\n===== SUMMARY =====" << std::endl;
std::cout << "End-to-end packet latency: " << latency_per_packet * 1e6 << " us" << std::endl;
std::cout << "Overall throughput: " << throughput_packets_per_second << " packets/sec" << std::endl;
std::cout << "Throughput (kernel only): " 
          << (packet_count / (kernel_ms / 1000.0)) << " packets/sec" << std::endl;
std::cout << "Throughput (file writing only): " 
          << (throughput_packets_per_second * (write_time / total_time)) << " packets/sec" << std::endl;



    return 0;
}
