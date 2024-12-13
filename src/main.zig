//! By convention, main.zig is where your main function lives in the case that
//! you are building an executable. If you are making a library, the convention
//! is to delete this file and start with root.zig instead.
const std = @import("std");
const elf = std.elf;
const c = @cImport({
    @cInclude("libdwarf/libdwarf.h");
    @cInclude("libelf.h");
    @cInclude("gelf.h");
});

// Write a function that takes an address, looks into all the FUNC entries in
// the symbol table, and returns the name of the function that contains that
// address.
pub fn getFunctionName(elf_handle: *c.Elf, addr: i64, allocator: std.mem.Allocator) ![]const u8 {
    var symbol: elf.Elf64_Sym = undefined;
    var scn: ?*c.Elf_Scn = null;
    scn = @ptrCast(c.elf_nextscn(elf_handle, scn));
    while (scn != null) : (scn = @ptrCast(c.elf_nextscn(elf_handle, scn))) {
        const shdr: ?*elf.Elf64_Shdr = @ptrCast(c.elf64_getshdr(scn));
        if ((shdr == null) or ((shdr.?.sh_type != elf.SHT_SYMTAB) and (shdr.?.sh_type != elf.SHT_DYNSYM))) continue;

        var data: ?*c.Elf_Data = null;
        data = @ptrCast(c.elf_getdata(scn, data));
        while (data != null) : (data = c.elf_getdata(scn, data)) {
            const symbols_container: ?*c.Elf_Data = @ptrCast(@alignCast(data));
            const symbols_cnt: usize = @divExact(symbols_container.?.d_size, @sizeOf(elf.Elf64_Sym));
            const symbols: [*]elf.Elf64_Sym = @ptrCast(@alignCast(symbols_container.?.d_buf));
            for (0..symbols_cnt) |i| {
                if ((symbols[i].st_type() == elf.STT_FUNC) and ((symbols[i].st_value <= addr) and (symbols[i].st_value + symbols[i].st_size >= addr))) {
                    symbol = symbols[i];
                    break;
                }
            }
        }
    }
    scn = null;
    scn = @ptrCast(c.elf_nextscn(elf_handle, scn));
    while (scn != null) : (scn = @ptrCast(c.elf_nextscn(elf_handle, scn))) {
        const shdr: ?*elf.Elf64_Shdr = @ptrCast(c.elf64_getshdr(scn));
        if ((shdr == null) or (shdr.?.sh_type != elf.SHT_STRTAB)) continue;
        var data: ?*c.Elf_Data = null;
        data = @ptrCast(c.elf_getdata(scn, data));
        while (data != null) : (data = c.elf_getdata(scn, data)) {
            const strings_container: ?*c.Elf_Data = @ptrCast(@alignCast(data));
            const strings_num = @divExact(strings_container.?.d_size, @sizeOf(u8));
            if (strings_num < symbol.st_name) continue;
            const strings: [*]u8 = @ptrCast(@alignCast(strings_container.?.d_buf));
            var symbol_name = std.ArrayList(u8).init(allocator);
            var stream = std.io.fixedBufferStream(strings[symbol.st_name .. symbol.st_name + 100]);
            try stream.reader().streamUntilDelimiter(symbol_name.writer(), 0, null);
            return symbol_name.items;
        }
    }
    unreachable;
}

// Little Endian Base 128
// variable length code compression used to store arbitrarily large integers
// in small number of bytes
const CIE = struct {
    length: u32,
    cie_id: u32,
    version: u8,
    augmentation_string: ?[]u8,
    // arbitray length, cause leb128 encoding
    // This is multiplied with the delta argument
    // of an advance location instruction to obtain
    // a  new location value
    code_alignment_factor: u32,
    // arbitray length, cause leb128 encoding
    // This is multiplied with the register offset
    // argument of an offset instruction to obtain
    // the new offset value
    data_alignment_factor: i32,
    //INFO: Not sure about the next one
    return_address_register: u32,
    //
    // Leb128 encoded value indicating length
    // in bytes of the augmentation data
    // only present if augmentation string
    // contains the character 'z'
    augmentation_length: ?u32,
    // augmentation data block
    augmentation_data: ?[]const u8,
    // initial set of call frame instructions
    initial_instructions: std.ArrayList(std.debug.Dwarf.call_frame.Instruction),
    padding: u32, // Unsure about the size
    const Self = @This();
    fn parse(stream: *std.io.FixedBufferStream([]u8)) !void {
        // 4 bytes
        const reader = stream.reader();
        const len = try reader.readInt(u32, .little);
        const cieId = try reader.readInt(u32, .little);
        const version = try reader.readInt(u8, .little);
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();
        const allocator = arena.allocator();
        //const cie = try allocator.create(CIE);
        var fde = std.ArrayList(u8).init(allocator);
        const stringWriter = fde.writer();
        try reader.streamUntilDelimiter(stringWriter, 0, null);
        const code_alignment = try std.leb.readUleb128(u32, reader);
        const data_alignment = try std.leb.readIleb128(i32, reader);
        const return_address_register = try std.leb.readUleb128(u32, reader);
        //cie.* = .{
        //    .length = len,
        //    .cie_id = cieId,
        //    .version = version,
        //    .augmentation_string = fde.items,
        //    .code_alignment_factor = code_alignment,
        //    .data_alignment_factor = data_alignment,
        //    .return_address_register = return_address_register,
        //};
        if (std.mem.containsAtLeast(u8, fde.items, 1, "z")) {
            const augmentation_length = try std.leb.readUleb128(u32, reader);
            const augmentation_data = stream.buffer[reader.context.pos..][0..augmentation_length];
            _ = augmentation_data;
            reader.context.pos += augmentation_length;
            while (true) {
                const inst = try std.debug.Dwarf.call_frame.Instruction.read(
                    @ptrCast(@constCast(stream)),
                    32,
                    .little,
                );
                if (std.meta.activeTag(inst) == .nop) {
                    break;
                }
                // std.log.warn("inst = {any}\n", .{inst});
            }
        }
        std.debug.print("stream_pos = {}, len = {}\n", .{ stream.pos, len });
        stream.pos = len + 4;
        std.debug.print("len: {}, cieId = {}, version = {}, fde={s}, code_alignment={}, data_alignment = {},return_address_register = {}\n", .{
            len,
            cieId,
            version,
            fde.items,
            code_alignment,
            data_alignment,
            return_address_register,
        });
    }
};

const FDE = struct {
    length: u32,
    cie_ptr: u32,
    initial_loc: u64,
    address_range: u64,
    instructions: std.ArrayList(std.debug.Dwarf.call_frame.Instruction),
    fn parse(stream: *std.io.FixedBufferStream([]u8)) !void {
        std.log.warn("Beginning FDE parse", .{});
        const reader = stream.reader();
        const len = try reader.readInt(u32, .little);
        const cie_ptr = try reader.readInt(u32, .little);
        const fde_ptr = try std.leb.readUleb128(u32, reader);
        std.debug.print("len = {}, cie_ptr={x}, fde={}\n", .{
            len,
            cie_ptr,
            fde_ptr,
        });
    }
};

pub fn parseEhHeader() !void {
    var file = try std.fs.cwd().openFile("./a", .{});
    defer file.close();
    var buffer: [32168]u8 = undefined;
    _ = try file.read(&buffer);
    var stream = std.io.fixedBufferStream(&buffer);
    const reader = stream.reader();
    const elfHeader = try reader.readStruct(std.elf.Elf64_Ehdr);
    const sectionNumber = elfHeader.e_shnum;
    const shstrndx = elfHeader.e_shstrndx;
    var sectionIndx: usize = 0;
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var sectionHeaders = std.ArrayList(std.elf.Elf64_Shdr).init(allocator);
    while (sectionIndx < sectionNumber) {
        const shdr: *align(1) const std.elf.Elf64_Shdr = @ptrCast(buffer[elfHeader.e_shoff + sectionIndx * elfHeader.e_shentsize ..][0..elfHeader.e_shentsize]);
        try sectionHeaders.append(shdr.*);
        sectionIndx += 1;
    }
    const sectionHeaderStringTable = sectionHeaders.items[shstrndx];
    const ehFrameSection = getSection(sectionHeaders, sectionHeaderStringTable, ".eh_frame", &buffer).?;
    _ = getSection(sectionHeaders, sectionHeaderStringTable, ".eh_frame_hdr", &buffer).?;
    const ehFrame = buffer[ehFrameSection.sh_offset..][0..ehFrameSection.sh_size];
    var ehFrameStream = std.io.fixedBufferStream(ehFrame);
    try CIE.parse(&ehFrameStream);
    try FDE.parse(&ehFrameStream);
}

pub fn getSection(sectionsList: std.ArrayList(std.elf.Elf64_Shdr), shstrtab: std.elf.Elf64_Shdr, sectionName: []const u8, buffer: []u8) ?std.elf.Elf64_Shdr {
    var index: usize = 0;
    while (index < sectionsList.items.len) {
        const currentSection = sectionsList.items[index];
        var currentSectionName = buffer[shstrtab.sh_offset..][currentSection.sh_name..];
        const zero = [_]u8{0};
        const terminationIndex = std.mem.indexOf(u8, currentSectionName, &zero).?;
        if (std.mem.eql(u8, sectionName, currentSectionName[0..terminationIndex])) {
            return currentSection;
        }
        index += 1;
    }
    return null;
}

pub fn readMemRelRBP(offset: i64) i64 {
    var out: i64 = undefined;
    asm volatile (
        \\ mov (%rbp, %[offset]), %[out]
        : [out] "=r" (out),
        : [offset] "r" (offset),
        : "memory"
    );
    return out;
}

pub fn main() !void {
    var elf_fd = try std.fs.cwd().openFile("./zig-out/bin/zig-unwind", .{});
    defer elf_fd.close();

    var elf_handle: ?*c.Elf = undefined;
    if (c.elf_version(c.EV_CURRENT) == c.EV_NONE) {
        std.debug.print("Error: libelf version mismatch\n", .{});
        return error.LibelfVersionMismatch;
    }

    elf_handle = c.elf_begin(elf_fd.handle, c.ELF_C_READ, null);
    if (elf_handle == null) {
        std.debug.print("Error opening ELF file: {s}\n", .{c.elf_errmsg(-1)});
        return error.ElfOpenError;
    }
    // defer _ = c.elf_end(elf_handle);

    // Initialize libdwarf with the ELF handle
    var dbg: c.Dwarf_Debug = undefined;
    var err: c.Dwarf_Error = undefined;
    const res = c.dwarf_elf_init(elf_handle, c.DW_DLC_READ, null, null, &dbg, &err);
    if (res != c.DW_DLV_OK) {
        std.debug.print("Error initializing libdwarf: {s}\n", .{c.dwarf_errmsg(err)});
        return error.DwarfInitError;
    }
    // defer _ = c.dwarf_elf_end(dbg, &err);

    // Get the .eh_frame section
    var fde_list: [*c]c.Dwarf_Fde = undefined;
    var fde_count: c.Dwarf_Signed = undefined;
    var cie_list: [*c]c.Dwarf_Cie = undefined;
    var cie_count: c.Dwarf_Signed = undefined;

    const fde_res = c.dwarf_get_fde_list_eh(dbg, &cie_list, &cie_count, &fde_list, &fde_count, &err);
    std.debug.print("CIE COUNT={}\n", .{cie_count});
    if (fde_res != c.DW_DLV_OK) {
        std.debug.print("Error getting FDE list from .eh_frame: {s}\n", .{c.dwarf_errmsg(err)});
        return error.DwarfFdeError;
    }

    var sp: usize = undefined;
    var bp: usize = undefined;
    var pc: i64 = undefined;

    // Use inline assembly to get the stack pointer (SP) and base pointer (BP)
    asm volatile (
        \\ mov %rsp,%[sp]
        \\ mov %rbp,%[bp]
        \\ lea 0(%rip),%[pc]
        : [sp] "=r" (sp),
          [bp] "=r" (bp),
          [pc] "=r" (pc),
        :
        : "memory"
    );

    std.debug.print("Stack Pointer (SP): 0x{x}\n", .{sp});
    std.debug.print("Base Pointer (BP): 0x{x}\n", .{bp});
    std.debug.print("Program counter (PC): 0x{x}\n", .{pc});

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    // Iterate through the FDEs
    var i: usize = 0;
    while (i < fde_count) : (i += 1) {
        var low_pc: c.Dwarf_Addr = undefined;
        var func_length: c.Dwarf_Unsigned = undefined;
        var fde_byte_length: c.Dwarf_Unsigned = undefined;
        // var fde_bytes: ?*anyopaque = undefined;
        var cie_offset: c.Dwarf_Off = undefined;
        var cie_index: c.Dwarf_Signed = undefined;
        var fde_off: c.Dwarf_Off = undefined;
        const range_res = c.dwarf_get_fde_range(
            fde_list[i],
            &low_pc,
            &func_length,
            null,
            &fde_byte_length,
            &cie_offset,
            &cie_index,
            &fde_off,
            &err,
        );
        if (range_res == c.DW_DLV_OK) {
            // std.debug.print("cie index: {} and offset = {}, fde_offset ={}\n", .{
            //     cie_index,
            //     cie_offset,
            //     fde_off,
            // });
            if (low_pc <= pc and pc <= (low_pc + func_length)) {
                // std.debug.print("This is my fde", .{});

                var cie_len: c.Dwarf_Unsigned = undefined;
                var version: c.Dwarf_Small = undefined;
                var augmenter: [*c]u8 = undefined;
                var code_alignment_factor: c.Dwarf_Unsigned = undefined;
                var data_alignment_factor: c.Dwarf_Signed = undefined;
                var return_addr_register: c.Dwarf_Half = undefined;
                var dw_initial_instructions = try allocator.alloc(u8, 4096);
                const opaque_ptr: [*c]?*anyopaque = @ptrCast(@alignCast(&dw_initial_instructions));
                var dw_initial_instructions_len: c.Dwarf_Unsigned = undefined;
                var offset_size: c.Dwarf_Half = undefined;
                var rc = c.dwarf_get_cie_info_b(
                    cie_list[@intCast(cie_index)],
                    &cie_len,
                    &version,
                    &augmenter,
                    &code_alignment_factor,
                    &data_alignment_factor,
                    &return_addr_register,
                    opaque_ptr,
                    &dw_initial_instructions_len,
                    &offset_size,
                    &err,
                );
                std.debug.assert(rc == c.DW_DLV_OK);
                //std.debug.print("cie_index = {}\n", .{cie_index});
                //std.debug.print("pc = {x} to pc = {x}\n", .{
                //    low_pc,
                //    low_pc + func_length,
                //});
                // std.debug.print("Don't know if this works: return_addr_register={any}, offset_size={}, augmenter={s}\n", .{
                //     return_addr_register,
                //     data_alignment_factor,
                //     augmenter,
                // });
                const unwindCtx = try allocator.create(UnwindContext);
                unwindCtx.pc = low_pc;
                unwindCtx.target_pc = pc;
                unwindCtx.code_alignment_factor = code_alignment_factor;
                // std.log.warn("dwarf instructions: {any}\n", .{dw_initial_instructions[0..dw_initial_instructions_len]});
                var stream = std.io.fixedBufferStream(@as(
                    []const u8,
                    @ptrCast(dw_initial_instructions[0..dw_initial_instructions_len]),
                ));
                //std.log.warn("dw_initial_instructions_len = {}, offset_size={}\n", .{
                //    dw_initial_instructions_len,
                //    offset_size,
                //});
                var instruction: std.debug.Dwarf.call_frame.Instruction = undefined;
                while (stream.pos < (try stream.getEndPos())) {
                    instruction = try std.debug.Dwarf.call_frame.Instruction.read(&stream, 64, .little);
                    //std.log.warn("instruction: {any}\n", .{instruction});
                    if (std.meta.activeTag(instruction) == .nop) break;
                    evalInstruction(unwindCtx, &instruction);
                }
                var fdeInstructions = try allocator.alloc(u8, 4096);
                const fde_opaque_ptr: [*c]?*anyopaque = @ptrCast(@alignCast(&fdeInstructions));
                var fde_out_len: c.Dwarf_Unsigned = undefined;
                err = undefined;
                rc = c.dwarf_get_fde_instr_bytes(
                    fde_list[i],
                    fde_opaque_ptr,
                    &fde_out_len,
                    &err,
                );
                instruction = undefined;
                stream = std.io.fixedBufferStream(
                    @as(
                        []const u8,
                        @ptrCast(fdeInstructions[0..fde_out_len]),
                    ),
                );

                while (stream.pos < (try stream.getEndPos())) {
                    instruction = try std.debug.Dwarf.call_frame.Instruction.read(&stream, 64, .little);
                    //std.log.warn("instruction: {any}\n", .{instruction});
                    if (std.meta.activeTag(instruction) == .nop) break;
                    evalInstruction(unwindCtx, &instruction);
                }

                //std.debug.print("pc = 0x{x}, target_pc = 0x{x}, cfa={any}, sp=0x{x}\n", .{
                //    unwindCtx.pc,
                //    unwindCtx.target_pc,
                //    unwindCtx.cfa,
                //    unwindCtx.registers[6],
                //});
                const ret_offset: i64 = unwindCtx.cfa.o + unwindCtx.registers[return_addr_register] * data_alignment_factor;
                const ret_address = readMemRelRBP(ret_offset);
                //std.log.warn("Return address: 0x{x}", .{ret_address});
                const fnName = try getFunctionName(elf_handle.?, pc, allocator);
                const lastFnName = try getFunctionName(elf_handle.?, ret_address, allocator);
                std.log.warn("Return address: 0x{x}\n", .{ret_address});
                std.log.warn("Start of backtrace:", .{});
                std.log.warn("{s}\n", .{fnName});
                std.log.warn("{s}\n", .{lastFnName});
            }
            // std.debug.print("FDE: range 0x{x} - 0x{x}\n", .{ low_pc, low_pc + func_length });
        }
    }

    // Clean up
    // c.dwarf_dealloc_fde_cie_list(dbg, null, 0, fde_list, fde_count);
}

const UnwindContext = struct {
    cfa: struct { r: u8, o: i64 },
    pc: u64,
    target_pc: i64,
    code_alignment_factor: u64,
    registers: [255]i64,
};

pub fn evalInstruction(ctx: *UnwindContext, instruction: *std.debug.Dwarf.call_frame.Instruction) void {
    if (ctx.pc > ctx.target_pc) return;
    switch (instruction.*) {
        .nop => {},
        .def_cfa => |def_cfa| {
            // std.log.warn("Executing def_cfa: register = {} and offset = {}\n", .{ def_cfa.register, def_cfa.offset });
            ctx.cfa = .{
                .r = def_cfa.register,
                .o = @intCast(def_cfa.offset),
            };
        },
        .def_cfa_sf => |def_cfa| {
            ctx.cfa = .{
                .r = def_cfa.register,
                .o = def_cfa.offset,
            };
        },
        .def_cfa_offset => |def_cfa| {
            ctx.cfa.o = @intCast(def_cfa.offset);
        },
        .def_cfa_register => |def_cfa| {
            ctx.cfa.r = def_cfa.register;
        },
        .def_cfa_offset_sf => |def_cfa| {
            ctx.cfa.o = def_cfa.offset;
        },
        .offset => |off| {
            ctx.registers[off.register] = @intCast(off.offset);
        },
        .offset_extended => |off_ext| {
            ctx.registers[off_ext.register] = @intCast(off_ext.offset);
        },
        .advance_loc => |adv_loc| {
            // std.log.warn("Executing adv_loc: delta = {}\n", .{adv_loc.delta * ctx.code_alignment_factor});
            ctx.pc += adv_loc.delta * ctx.code_alignment_factor;
        },
        .advance_loc1 => |adv_loc| {
            // std.log.warn("Executing adv_loc: delta = {}\n", .{adv_loc.delta * ctx.code_alignment_factor});
            ctx.pc += adv_loc.delta * ctx.code_alignment_factor;
        },
        .advance_loc2 => |adv_loc| {
            // std.log.warn("Executing adv_loc: delta = {}\n", .{adv_loc.delta * ctx.code_alignment_factor});
            ctx.pc += adv_loc.delta * ctx.code_alignment_factor;
        },
        .advance_loc4 => |adv_loc| {
            // std.log.warn("Executing adv_loc: delta = {}\n", .{adv_loc.delta * ctx.code_alignment_factor});
            ctx.pc += adv_loc.delta * ctx.code_alignment_factor;
        },
        else => {
            std.log.warn(
                "instruction kind: {}\n",
                .{std.meta.activeTag(instruction.*)},
            );
            unreachable;
        },
    }
}

test "simple test" {
    var list = std.ArrayList(i32).init(std.testing.allocator);
    defer list.deinit(); // Try commenting this out and see if zig detects the memory leak!
    try list.append(42);
    try std.testing.expectEqual(@as(i32, 42), list.pop());
}

test "fuzz example" {
    const global = struct {
        fn testOne(input: []const u8) anyerror!void {
            // Try passing `--fuzz` to `zig build test` and see if it manages to fail this test case!
            try std.testing.expect(!std.mem.eql(u8, "canyoufindme", input));
        }
    };
    try std.testing.fuzz(global.testOne, .{});
}
