#include <ida.hpp>
#include <idp.hpp>
#include <ua.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <offset.hpp>

#define NAME "M68000 proc-fixer plugin"
#define VERSION "1.0"

static bool plugin_inited;
static bool my_dbg;

enum m68k_insn_type_t
{
    M68K_linea = CUSTOM_INSN_ITYPE,
    M68K_linef,
};

//--------------------------------------------------------------------------
static void print_version()
{
    static const char format[] = NAME " v%s\n";
    info(format, VERSION);
    msg(format, VERSION);
}

//--------------------------------------------------------------------------
static bool init_plugin(void)
{
    if (ph.id != PLFM_68K)
        return false;

    return true;
}

#ifdef _DEBUG
static const char* const optype_names[] =
{
    "o_void",
    "o_reg",
    "o_mem",
    "o_phrase",
    "o_displ",
    "o_imm",
    "o_far",
    "o_near",
    "o_idpspec0",
    "o_idpspec1",
    "o_idpspec2",
    "o_idpspec3",
    "o_idpspec4",
    "o_idpspec5",
};

static const char* const dtyp_names[] =
{
    "dt_byte",
    "dt_word",
    "dt_dword",
    "dt_float",
    "dt_double",
    "dt_tbyte",
    "dt_packreal",
    "dt_qword",
    "dt_byte16",
    "dt_code",
    "dt_void",
    "dt_fword",
    "dt_bitfild",
    "dt_string",
    "dt_unicode",
    "dt_3byte",
    "dt_ldbl",
    "dt_byte32",
    "dt_byte64",
};

static void print_insn(const insn_t *insn)
{
    if (my_dbg)
    {
        msg("cs=%x, ", insn->cs);
        msg("ip=%x, ", insn->ip);
        msg("ea=%x, ", insn->ea);
        msg("itype=%x, ", insn->itype);
        msg("size=%x, ", insn->size);
        msg("auxpref=%x, ", insn->auxpref);
        msg("segpref=%x, ", insn->segpref);
        msg("insnpref=%x, ", insn->insnpref);
        msg("insnpref=%x, ", insn->insnpref);

        msg("flags[");
        if (insn->flags & INSN_MACRO)
            msg("INSN_MACRO|");
        if (insn->flags & INSN_MODMAC)
            msg("OF_OUTER_DISP");
        msg("]\n");
    }
}

static void print_op(ea_t ea, const op_t *op)
{
    if (my_dbg)
    {
        msg("type[%s], ", optype_names[op->type]);

        msg("flags[");
        if (op->flags & OF_NO_BASE_DISP)
            msg("OF_NO_BASE_DISP|");
        if (op->flags & OF_OUTER_DISP)
            msg("OF_OUTER_DISP|");
        if (op->flags & PACK_FORM_DEF)
            msg("PACK_FORM_DEF|");
        if (op->flags & OF_NUMBER)
            msg("OF_NUMBER|");
        if (op->flags & OF_SHOW)
            msg("OF_SHOW");
        msg("], ");

        msg("dtyp[%s], ", dtyp_names[op->dtype]);

        if (op->type == o_reg)
            msg("reg=%x, ", op->reg);
        else if (op->type == o_displ || op->type == o_phrase)
            msg("phrase=%x, ", op->phrase);
        else
            msg("reg_phrase=%x, ", op->phrase);

        msg("addr=%x, ", op->addr);

        msg("value=%x, ", op->value);

        msg("specval=%x, ", op->specval);

        msg("specflag1=%x, ", op->specflag1);
        msg("specflag2=%x, ", op->specflag2);
        msg("specflag3=%x, ", op->specflag3);
        msg("specflag4=%x, ", op->specflag4);

        msg("refinfo[");

        opinfo_t buf;

        if (get_opinfo(&buf, ea, op->n, op->flags))
        {
            msg("target=%x, ", buf.ri.target);
            msg("base=%x, ", buf.ri.base);
            msg("tdelta=%x, ", buf.ri.tdelta);

            msg("flags[");
            if (buf.ri.flags & REFINFO_TYPE)
                msg("REFINFO_TYPE|");
            if (buf.ri.flags & REFINFO_RVAOFF)
                msg("REFINFO_RVAOFF|");
            if (buf.ri.flags & REFINFO_PASTEND)
                msg("REFINFO_PASTEND|");
            if (buf.ri.flags & REFINFO_CUSTOM)
                msg("REFINFO_CUSTOM|");
            if (buf.ri.flags & REFINFO_NOBASE)
                msg("REFINFO_NOBASE|");
            if (buf.ri.flags & REFINFO_SUBTRACT)
                msg("REFINFO_SUBTRACT|");
            if (buf.ri.flags & REFINFO_SIGNEDOP)
                msg("REFINFO_SIGNEDOP");
            msg("]");
        }
        msg("]\n");
    }
}
#endif

static bool ana_addr = 0;

static ssize_t idaapi hook_idp(void *user_data, int notification_code, va_list va)
{
    switch (notification_code)
    {
    case processor_t::ev_ana_insn:
    {
        insn_t *out = va_arg(va, insn_t*);

        if (ana_addr)
            break;

        uint16 itype = 0;
        ea_t value = out->ea;
        uchar b = get_byte(out->ea);

        if (b == 0xA0 || b == 0xF0)
        {
            switch (b)
            {
            case 0xA0:
                itype = M68K_linea;
                value = get_dword(0x0A * sizeof(uint32));
                break;
            case 0xF0:
                itype = M68K_linef;
                value = get_dword(0x0B * sizeof(uint32));
                break;
            }

            out->itype = itype;
            out->size = 2;

            out->Op1.type = o_near;
            out->Op1.offb = 1;
            out->Op1.dtype = dt_dword;
            out->Op1.addr = value;
            out->Op1.phrase = 0x0A;
            out->Op1.specflag1 = 2;

            out->Op2.type = o_imm;
            out->Op2.offb = 1;
            out->Op2.dtype = dt_byte;
            out->Op2.value = get_byte(out->ea + 1);
        }
        else
        {
            ana_addr = 1;

            if (ph.ana_insn(out) <= 0)
            {
                ana_addr = 0;
                break;
            }

            ana_addr = 0;

#ifdef _DEBUG
            print_insn(out);
#endif

            for (int i = 0; i < UA_MAXOP; ++i)
            {
                op_t &op = out->ops[i];

#ifdef _DEBUG
                print_op(out->ea, &op);
#endif

                switch (op.type)
                {
                case o_near:
                case o_mem:
                {
                    op.addr &= 0xFFFFFF; // for any mirrors

                    if ((op.addr & 0xE00000) == 0xE00000) // RAM mirrors
                        op.addr |= 0x1F0000;

                    if ((op.addr >= 0xC00000 && op.addr <= 0xC0001F) ||
                        (op.addr >= 0xC00020 && op.addr <= 0xC0003F)) // VDP mirrors
                        op.addr &= 0xC000FF;

                    if (out->itype != 0x76 || op.n != 0 ||
                        (op.phrase != 0x09 && op.phrase != 0x0A) ||
                        (op.addr == 0 || op.addr >= (1 << 23)) ||
                        op.specflag1 != 2) // lea table(pc),Ax
                        break;

                    short diff = op.addr - out->ea;
                    if (diff >= SHRT_MIN && diff <= SHRT_MAX)
                    {
                        out->Op1.type = o_displ;
                        out->Op1.offb = 2;
                        out->Op1.dtype = dt_dword;
                        out->Op1.phrase = 0x5B;
                        out->Op1.specflag1 = 0x10;
                    }
                } break;
                case o_imm:
                {
                    if (out->itype != 0x7F || op.n != 0) // movea
                        break;

                    if (op.value & 0xFF0000 && op.dtype == dt_word) {
                        op.value &= 0xFFFF;
                    }
                } break;
                }
            }
        }

        return out->size;
    } break;
    case processor_t::ev_emu_insn:
    {
        const insn_t *insn = va_arg(va, const insn_t*);

        for (int i = 0; i < UA_MAXOP; ++i)
        {
            const op_t &op = insn->ops[i];

            switch (op.type)
            {
            case o_imm:
            {
                if (insn->itype != 0x7F || op.n != 0 || op.dtype != dt_word) // movea
                    break;

                op_offset(insn->ea, op.n, REF_OFF32, BADADDR, 0xFF0000);
            } break;
            }
        }

        if (insn->itype == 0xB6) // trap #X
        {
            qstring name;
            ea_t trap_addr = get_dword((0x20 + (insn->Op1.value & 0xF)) * sizeof(uint32));
            get_func_name(&name, trap_addr);
            set_cmt(insn->ea, name.c_str(), false);
            insn->add_cref(trap_addr, insn->Op1.offb, fl_CN);
            return 1;
        }

        if (insn->itype == M68K_linea || insn->itype == M68K_linef)
        {
            insn->add_cref(insn->Op1.addr, 0, fl_CN);
            insn->add_cref(insn->ea + insn->size, insn->Op1.offb, fl_F);
            return 1;
        }
    } break;
    case processor_t::ev_out_mnem:
    {
        outctx_t *outbuffer = va_arg(va, outctx_t *);

        if (outbuffer->insn.itype != M68K_linea && outbuffer->insn.itype != M68K_linef)
            break;

        const char *mnem = (outbuffer->insn.itype == M68K_linef) ? "line_f" : "line_a";

        outbuffer->out_custom_mnem(mnem);
        return 1;
    } break;
    default:
    {
#ifdef _DEBUG
        if (my_dbg)
        {
            msg("msg = %d\n", notification_code);
        }
#endif
    } break;
    }
    return 0;
}

//--------------------------------------------------------------------------
static int idaapi init(void)
{
    if (init_plugin())
    {
        plugin_inited = true;
        my_dbg = false;

        hook_to_notification_point(HT_IDP, hook_idp, NULL);

        print_version();
        return PLUGIN_KEEP;
    }
    return PLUGIN_SKIP;
}

//--------------------------------------------------------------------------
static void idaapi term(void)
{
    if (plugin_inited)
    {
        unhook_from_notification_point(HT_IDP, hook_idp);

        plugin_inited = false;
    }
}

//--------------------------------------------------------------------------
static bool idaapi run(size_t /*arg*/)
{
    return false;
}

//--------------------------------------------------------------------------
const char comment[] = NAME;
const char help[] = NAME;

//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
    IDP_INTERFACE_VERSION,
    PLUGIN_PROC | PLUGIN_MOD, // plugin flags
    init, // initialize

    term, // terminate. this pointer may be NULL.

    run, // invoke plugin

    comment, // long comment about the plugin
             // it could appear in the status line
             // or as a hint

    help, // multiline help about the plugin

    NAME, // the preferred short name of the plugin

    "" // the preferred hotkey to run the plugin
};
