/* Freestanding consumer for the pinned CXLMemSim-riscv SiFive U machine.
 * Guest loads use the CXL fixed memory window for Type 2 and Type 3.
 */
#include <stdint.h>

#define CXL_BASE UINT64_C(0x1000000000)
#define TYPE2_DPA_BASE UINT64_C(0x200000)
#define RP_CONFIG UINT64_C(0x34000000)
#define DEVICE_CONFIG UINT64_C(0x34100000)
#define COMPONENT_BAR UINT64_C(0x70000000)
#define CACHE_MEM (COMPONENT_BAR + UINT64_C(0x1000))
#define UART UINT64_C(0x10010000)
#define MAGIC UINT64_C(0x43584c4e49433031)
#define MAX_PAYLOAD 1500u
#define FLOWS 2u
#define WINDOW 4u
#define SLOT_BASE UINT64_C(0x10000)
#define SLOT_STRIDE UINT64_C(0x1000)

static uint8_t payload[MAX_PAYLOAD];
static int cxl_configured;
static uint64_t data_base = CXL_BASE;

static void fence_io(void)
{
    __asm__ volatile("fence iorw, iorw" ::: "memory");
}

static uint64_t load64(uint64_t address)
{
    return *(volatile uint64_t *)(uintptr_t)address;
}

static uint32_t load32(uint64_t address)
{
    return *(volatile uint32_t *)(uintptr_t)address;
}

static void store64(uint64_t address, uint64_t value)
{
    *(volatile uint64_t *)(uintptr_t)address = value;
}

static void store32(uint64_t address, uint32_t value)
{
    *(volatile uint32_t *)(uintptr_t)address = value;
}

static void store16(uint64_t address, uint16_t value)
{
    *(volatile uint16_t *)(uintptr_t)address = value;
}

static void uart_char(char ch)
{
    while (load32(UART) & UINT32_C(0x80000000)) {
        __asm__ volatile("nop");
    }
    store32(UART, (uint8_t)ch);
}

static void uart_text(const char *text)
{
    while (*text) {
        uart_char(*text++);
    }
}

static void uart_uint(uint64_t value)
{
    char digits[20];
    unsigned count = 0;
    do {
        digits[count++] = (char)('0' + value % 10);
        value /= 10;
    } while (value);
    while (count) {
        uart_char(digits[--count]);
    }
}

static void uart_field(uint64_t value)
{
    uart_char(' ');
    uart_uint(value);
}

__attribute__((noreturn)) static void park(void)
{
    for (;;) {
        __asm__ volatile("wfi");
    }
}

__attribute__((noreturn)) static void fail(uint64_t code, uint64_t flow,
                                         uint64_t serial, uint64_t offset)
{
    uart_text("FAIL");
    uart_field(code);
    uart_field(flow);
    uart_field(serial);
    uart_field(offset);
    uart_char('\n');
    if (cxl_configured) {
        fence_io();
        store64(data_base + 64, UINT64_C(0x100) + code);
        fence_io();
    }
    park();
}

__attribute__((noreturn)) void guest_trap(uint64_t cause, uint64_t pc,
                                        uint64_t address)
{
    /* A bus fault cannot safely write the status through that same aperture. */
    cxl_configured = 0;
    uart_text("TRAP");
    uart_field(cause);
    uart_field(pc);
    uart_field(address);
    uart_char('\n');
    fail(3, 0, 0, address);
}

static void configure_cxl(void)
{
    uint32_t id = load32(RP_CONFIG);
    int type2;
    if ((id & UINT32_C(0xffff)) == UINT32_C(0xffff) || !(id & 0xffff)) {
        fail(3, 0, 0, RP_CONFIG);
    }
    store32(RP_CONFIG + 0x18, UINT32_C(0x00414140));
    /* CXL MMIO32 is 0x70000000..0x7fffffff on this machine. */
    store32(RP_CONFIG + 0x20, UINT32_C(0x70007000));
    /* Type2 BAR4 uses 0x400000000..0x40fffffff; BAR2 follows it. */
    store32(RP_CONFIG + 0x24, UINT32_C(0x10010001));
    store32(RP_CONFIG + 0x28, 4);
    store32(RP_CONFIG + 0x2c, 4);
    store16(RP_CONFIG + 0x04, 6);
    fence_io();
    id = load32(DEVICE_CONFIG);
    if ((id & UINT32_C(0xffff)) == UINT32_C(0xffff) || !(id & 0xffff)) {
        fail(3, 0, 0, DEVICE_CONFIG);
    }
    type2 = (id & UINT32_C(0xffff)) == UINT32_C(0x8086) &&
            (id >> 16) == UINT32_C(0x0d92);
    store32(DEVICE_CONFIG + 0x10, UINT32_C(0x70000004));
    store32(DEVICE_CONFIG + 0x14, 0);
    if (type2) {
        store32(DEVICE_CONFIG + 0x18, UINT32_C(0x1000000c));
        store32(DEVICE_CONFIG + 0x1c, 4);
        store32(DEVICE_CONFIG + 0x20, UINT32_C(0x0000000c));
        store32(DEVICE_CONFIG + 0x24, 4);
    }
    store16(DEVICE_CONFIG + 0x04, 6);
    fence_io();

    /* Pinned QEMU's CXL HDM capability starts at cache/mem offset 0x128.
     * One root port uses host bridge passthrough, so only the endpoint HDM
     * decoder is needed. Decoder 0 maps the 256 MiB FMW to DPA zero.
     */
    store32(CACHE_MEM + 0x12c, 2);
    store32(CACHE_MEM + 0x138, 0);
    store32(CACHE_MEM + 0x13c, 0x10);
    store32(CACHE_MEM + 0x140, UINT32_C(0x10000000));
    store32(CACHE_MEM + 0x144, 0);
    store32(CACHE_MEM + 0x14c, 0);
    store32(CACHE_MEM + 0x150, 0);
    store32(CACHE_MEM + 0x148, UINT32_C(0x200));
    fence_io();
    if ((load32(CACHE_MEM + 0x148) & UINT32_C(0xc00)) != UINT32_C(0x400)) {
        fail(3, 0, 0, CACHE_MEM + 0x148);
    }
    if (type2) {
        data_base = CXL_BASE + TYPE2_DPA_BASE;
    }
    cxl_configured = 1;
}

static uint64_t mix64(uint64_t value)
{
    value = (value ^ (value >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    value = (value ^ (value >> 27)) * UINT64_C(0x94d049bb133111eb);
    return value ^ (value >> 31);
}

static void consume_payload(uint64_t address, uint64_t length, uint64_t nonce,
                            uint64_t flow, uint64_t serial)
{
    uint64_t offset = 0;
    /* Copy real guest loads into ordinary DRAM before validation/logging. */
    while (offset + 8 <= length) {
        uint64_t word = load64(address + offset);
        for (unsigned byte = 0; byte < 8; ++byte) {
            payload[offset + byte] = (uint8_t)(word >> (byte * 8));
        }
        offset += 8;
    }
    while (offset < length) {
        payload[offset] = *(volatile uint8_t *)(uintptr_t)(address + offset);
        ++offset;
    }
    for (offset = 0; offset < length; ++offset) {
        uint64_t word = mix64(nonce ^ (flow << 56) ^
                             (serial * UINT64_C(0x9e3779b97f4a7c15)) ^
                             ((offset / 8) * UINT64_C(0xd6e8feb86659fd93)));
        uint8_t expected = (uint8_t)(word >> ((offset % 8) * 8));
        if (payload[offset] != expected) {
            fail(2, flow, serial, offset);
        }
    }
}

static void print_packet(const uint64_t descriptor[5])
{
    static const char hex[] = "0123456789abcdef";
    uart_text("PACKET");
    for (unsigned field = 0; field < 5; ++field) {
        uart_field(descriptor[field]);
    }
    uart_char(' ');
    for (uint64_t offset = 0; offset < descriptor[4]; ++offset) {
        uart_char(hex[payload[offset] >> 4]);
        uart_char(hex[payload[offset] & 15]);
    }
    uart_char('\n');
}

void guest_main(void)
{
    uint64_t control[8];
    uint64_t consumed[FLOWS] = {0, 0};
    uint64_t expected[FLOWS];
    uint64_t total = 0;

    configure_cxl();
    for (unsigned index = 0; index < 8; ++index) {
        control[index] = load64(data_base + index * 8);
    }
    fence_io();
    if (control[0] != MAGIC || control[2] == 0 ||
        control[2] > UINT64_MAX / FLOWS || control[5] != FLOWS ||
        control[6] != WINDOW || control[7] != MAX_PAYLOAD ||
        control[3] > UINT64_MAX - control[2] ||
        control[4] > UINT64_MAX - control[2]) {
        fail(3, 0, 0, 0);
    }
    expected[0] = control[3];
    expected[1] = control[4];
    fence_io();
    store64(data_base + 64, 1);
    fence_io();
    uart_text("READY\n");

    while (total < control[2] * FLOWS) {
        for (uint64_t flow = 0; flow < FLOWS; ++flow) {
            uint64_t serial, slot, generation, address, descriptor[5];
            if (consumed[flow] == control[2]) {
                continue;
            }
            serial = expected[flow];
            slot = serial % WINDOW;
            generation = consumed[flow] / WINDOW + 1;
            address = data_base + SLOT_BASE + (flow * WINDOW + slot) * SLOT_STRIDE;
            if (load64(address + 64) != generation) {
                continue;
            }
            fence_io();
            for (unsigned field = 0; field < 5; ++field) {
                descriptor[field] = load64(address + field * 8);
            }
            if (descriptor[0] != flow) {
                fail(1, flow, serial, 0);
            }
            if (descriptor[1] != serial) {
                fail(1, flow, serial, 8);
            }
            if (descriptor[2] != slot) {
                fail(1, flow, serial, 16);
            }
            if (descriptor[3] != generation) {
                fail(1, flow, serial, 24);
            }
            if (descriptor[4] == 0 || descriptor[4] > MAX_PAYLOAD) {
                fail(1, flow, serial, 32);
            }
            consume_payload(address + 256, descriptor[4], control[1], flow, serial);
            print_packet(descriptor);
            fence_io();
            store64(address + 128, generation);
            fence_io();
            ++expected[flow];
            ++consumed[flow];
            ++total;
        }
    }
    uart_text("DONE");
    uart_field(total);
    uart_char('\n');
    fence_io();
    store64(data_base + 64, 2);
    fence_io();
    park();
}
