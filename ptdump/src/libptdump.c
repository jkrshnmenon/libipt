/*
 * Copyright (c) 2013-2022, Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  * Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *  * Neither the name of Intel Corporation nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "pt_cpu.h"
#include "pt_last_ip.h"
#include "pt_time.h"
#include "pt_compiler.h"
#include "pt_version.h"

#include "intel-pt.h"
#include "sync.h"

#if defined(FEATURE_SIDEBAND)
#  include "libipt-sb.h"
#endif

#include <stdlib.h>
#include <stdarg.h>
#include <inttypes.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <limits.h>

#if defined(_MSC_VER) && (_MSC_VER < 1900)
#  define snprintf _snprintf_c
#endif


size_t *ip_table = NULL;
size_t ip_table_size, ip_table_ctr;


void append_to_table(size_t addr) {
	if ( ip_table_ctr == ip_table_size) {
		ip_table_size *= 2;
		ip_table = realloc(ip_table, ip_table_size * sizeof(size_t));

		if ( ip_table == NULL) {
			perror("realloc");
			exit(1);
		}
	}
	ip_table[ip_table_ctr++] = addr;
}

void fix_upper_bits(size_t current, int bit_len) {
	if (ip_table_ctr == 0 || bit_len == 64) {
		append_to_table(current);
		return;
	}

	size_t prev = ip_table[ip_table_ctr];	
	size_t actual = ((prev >> bit_len) << bit_len) + current;
	update_bb(actual);
	// append_to_table(actual);
	return;
}


void pp_table() {
	size_t i = 0;
	for ( i = 0; i < ip_table_ctr; i++) {
		printf("[%ld] 0x%016lx\n", i, ip_table[i]);
	}
	return;
}


struct ptdump_options {
#if defined(FEATURE_SIDEBAND)
	/* Sideband dump flags. */
	uint32_t sb_dump_flags;
#endif
	/* Show the current offset in the trace stream. */
	uint32_t show_offset:1;

	/* Show raw packet bytes. */
	uint32_t show_raw_bytes:1;

	/* Show last IP for packets with IP payloads. */
	uint32_t show_last_ip:1;

	/* Show the execution mode on mode.exec. */
	uint32_t show_exec_mode:1;

	/* Keep track of time. */
	uint32_t track_time:1;

	/* Show the estimated TSC for timing related packets. */
	uint32_t show_time:1;

	/* Show time calibration. */
	uint32_t show_tcal:1;

	/* Show timing information as delta to the previous value. */
	uint32_t show_time_as_delta:1;

	/* Preserve timing calibration on overflow. */
	uint32_t keep_tcal_on_ovf:1;

	/* Quiet mode: Don't print anything but errors. */
	uint32_t quiet:1;

	/* Don't show PAD packets. */
	uint32_t no_pad:1;

	/* Do not try to sync the decoder. */
	uint32_t no_sync:1;

	/* Do not calibrate timing. */
	uint32_t no_tcal:1;

	/* Do not expect wall-clock time. */
	uint32_t no_wall_clock:1;

	/* Don't show timing packets. */
	uint32_t no_timing:1;

	/* Don't show CYC packets and ignore them when tracking time. */
	uint32_t no_cyc:1;

#if defined(FEATURE_SIDEBAND)
	/* Print sideband warnings. */
	uint32_t print_sb_warnings:1;
#endif
};

struct ptdump_buffer {
	/* The trace offset. */
	char offset[17];

	/* The raw packet bytes. */
	char raw[33];

	/* The packet opcode. */
	char opcode[10];

	union {
		/* The standard packet payload. */
		char standard[25];

		/* An extended packet payload. */
		char extended[48];
	} payload;

	/* The tracking information. */
	struct {
		/* The tracking identifier. */
		char id[5];

		/* The tracking information. */
		char payload[17];
	} tracking;

	/* A flag telling whether an extended payload is used. */
	uint32_t use_ext_payload:1;

	/* A flag telling whether to skip printing this buffer. */
	uint32_t skip:1;

	/* A flag telling whether to skip printing the time. */
	uint32_t skip_time:1;

	/* A flag telling whether to skip printing the calibration. */
	uint32_t skip_tcal:1;
};

struct ptdump_tracking {
#if defined(FEATURE_SIDEBAND)
	/* The sideband session. */
	struct pt_sb_session *session;
#endif

	/* Track last-ip. */
	struct pt_last_ip last_ip;

	/* Track time calibration. */
	struct pt_time_cal tcal;

	/* Track time. */
	struct pt_time time;

	/* The last estimated TSC. */
	uint64_t tsc;

	/* The last calibration value. */
	uint64_t fcr;

	/* Header vs. normal decode.  Set if decoding PSB+. */
	uint32_t in_header:1;
};


static int no_file_error(const char *name)
{
	fprintf(stderr, "%s: No processor trace file specified.\n", name);
	return -1;
}

static int unknown_option_error(const char *arg, const char *name)
{
	fprintf(stderr, "%s: unknown option: %s.\n", name, arg);
	return -1;
}

static int load_file(uint8_t **buffer, size_t *psize, const char *filename,
		     uint64_t offset, uint64_t size, const char *prog)
{
	uint8_t *content;
	size_t read;
	FILE *file;
	unsigned long fsize, begin, end;
	int errcode;

	if (!buffer || !psize || !filename || !prog) {
		fprintf(stderr, "%s: internal error.\n", prog ? prog : "");
		return -1;
	}

	errno = 0;
	file = fopen(filename, "rb");
	if (!file) {
		fprintf(stderr, "%s: failed to open %s: %d.\n",
			prog, filename, errno);
		return -1;
	}

	errcode = fseek(file, 0, SEEK_END);
	if (errcode) {
		fprintf(stderr, "%s: failed to determine size of %s: %d.\n",
			prog, filename, errno);
		goto err_file;
	}

	fsize = ftell(file);
	if (fsize < 0) {
		fprintf(stderr, "%s: failed to determine size of %s: %d.\n",
			prog, filename, errno);
		goto err_file;
	}

	begin = (long) offset;
	if (((uint64_t) begin != offset) || (fsize <= begin)) {
		fprintf(stderr,
			"%s: bad offset 0x%" PRIx64 " into %s.\n",
			prog, offset, filename);
		goto err_file;
	}

	end = fsize;
	if (size) {
		uint64_t range_end;

		range_end = offset + size;
		if ((uint64_t) end < range_end) {
			fprintf(stderr,
				"%s: bad range 0x%" PRIx64 " in %s.\n",
				prog, range_end, filename);
			goto err_file;
		}

		end = (long) range_end;
	}

	fsize = end - begin;

	content = malloc((size_t) fsize);
	if (!content) {
		fprintf(stderr, "%s: failed to allocated memory %s.\n",
			prog, filename);
		goto err_file;
	}

	errcode = fseek(file, begin, SEEK_SET);
	if (errcode) {
		fprintf(stderr, "%s: failed to load %s: %d.\n",
			prog, filename, errno);
		goto err_content;
	}

	read = fread(content, (size_t) fsize, 1u, file);
	if (read != 1) {
		fprintf(stderr, "%s: failed to load %s: %d.\n",
			prog, filename, errno);
		goto err_content;
	}

	fclose(file);

	*buffer = content;
	*psize = (size_t) fsize;

	return 0;

err_content:
	free(content);

err_file:
	fclose(file);
	return -1;
}

static int load_pt(struct pt_config *config, const char *filename,
		   uint64_t foffset, uint64_t fsize, const char *prog)
{
	uint8_t *buffer;
	size_t size;
	int errcode;

	errcode = load_file(&buffer, &size, filename, foffset, fsize, prog);
	if (errcode < 0)
		return errcode;

	config->begin = buffer;
	config->end = buffer + size;

	return 0;
}

static int diag(const char *errstr, uint64_t offset, int errcode)
{
	if (errcode)
		printf("[%" PRIx64 ": %s: %s]\n", offset, errstr,
		       pt_errstr(pt_errcode(errcode)));
	else
		printf("[%" PRIx64 ": %s]\n", offset, errstr);

	return errcode;
}

static void ptdump_tracking_init(struct ptdump_tracking *tracking)
{
	if (!tracking)
		return;

	pt_last_ip_init(&tracking->last_ip);
	pt_tcal_init(&tracking->tcal);
	pt_time_init(&tracking->time);

#if defined(FEATURE_SIDEBAND)
	tracking->session = NULL;
#endif
	tracking->tsc = 0ull;
	tracking->fcr = 0ull;
	tracking->in_header = 0;
}

static void ptdump_tracking_reset(struct ptdump_tracking *tracking)
{
	if (!tracking)
		return;

	pt_last_ip_init(&tracking->last_ip);
	pt_tcal_init(&tracking->tcal);
	pt_time_init(&tracking->time);

	tracking->tsc = 0ull;
	tracking->fcr = 0ull;
	tracking->in_header = 0;
}

static void ptdump_tracking_fini(struct ptdump_tracking *tracking)
{
	if (!tracking)
		return;

#if defined(FEATURE_SIDEBAND)
	pt_sb_free(tracking->session);
#endif
}

#define print_field(field, ...)					\
	do {							\
		/* Avoid partial overwrites. */			\
		memset(field, 0, sizeof(field));		\
		snprintf(field, sizeof(field), __VA_ARGS__);	\
	} while (0)


#define do_printf(field, ...)					\
	do {										\
	} while (0)									\


static int print_buffer(struct ptdump_buffer *buffer, uint64_t offset,
			const struct ptdump_options *options)
{
	const char *sep;

	if (!buffer)
		return diag("error printing buffer", offset, -pte_internal);

	if (buffer->skip || options->quiet)
		return 0;

	/* Make sure the first column starts at the beginning of the line - no
	 * matter what column is first.
	 */
	sep = "";

	if (options->show_offset) {
		do_printf("%-*s", (int) sizeof(buffer->offset), buffer->offset);
		sep = " ";
	}

	if (buffer->raw[0]) {
		do_printf("%s%-*s", sep, (int) sizeof(buffer->raw), buffer->raw);
		sep = " ";
	}

	if (buffer->payload.standard[0])
		do_printf("%s%-*s", sep, (int) sizeof(buffer->opcode),
		       buffer->opcode);
	else
		do_printf("%s%s", sep, buffer->opcode);

	/* We printed at least one column.  From this point on, we don't need
	 * the separator any longer.
	 */

	if (buffer->use_ext_payload)
		do_printf(" %s", buffer->payload.extended);
	else if (buffer->tracking.id[0]) {
		do_printf(" %-*s", (int) sizeof(buffer->payload.standard),
		       buffer->payload.standard);

		do_printf(" %-*s", (int) sizeof(buffer->tracking.id),
		       buffer->tracking.id);
		do_printf("%s", buffer->tracking.payload);
	} else if (buffer->payload.standard[0])
		do_printf(" %s", buffer->payload.standard);

	do_printf("\n");
	return 0;
}

static int print_raw(struct ptdump_buffer *buffer, uint64_t offset,
		     const struct pt_packet *packet,
		     const struct pt_config *config)
{
	const uint8_t *begin, *end;
	char *bbegin, *bend;
	int len;

	if (!buffer || !packet)
		return diag("error printing packet", offset, -pte_internal);

	begin = config->begin + offset;
	end = begin + packet->size;

	if (config->end < end)
		return diag("bad packet size", offset, -pte_bad_packet);

	bbegin = buffer->raw;
	bend = bbegin + sizeof(buffer->raw);

	for (; begin < end; ++begin, bbegin += len) {
		size_t size = (size_t) ((uintptr_t) bend - (uintptr_t) bbegin);

		len = snprintf(bbegin, size, "%02x", *begin);
		if (len != 2)
			return diag("truncating raw packet", offset, 0);
	}

	return 0;
}

static int track_last_ip(struct ptdump_buffer *buffer,
			 struct pt_last_ip *last_ip, uint64_t offset,
			 const struct pt_packet_ip *packet,
			 const struct ptdump_options *options,
			 const struct pt_config *config)
{
	uint64_t ip;
	int errcode;

	if (!buffer || !options)
		return diag("error tracking last-ip", offset, -pte_internal);

	print_field(buffer->tracking.id, "ip");

	errcode = pt_last_ip_update_ip(last_ip, packet, config);
	if (errcode < 0) {
		print_field(buffer->tracking.payload, "<unavailable>");

		return diag("error tracking last-ip", offset, errcode);
	}

	errcode = pt_last_ip_query(&ip, last_ip);
	if (errcode < 0) {
		if (errcode == -pte_ip_suppressed)
			print_field(buffer->tracking.payload, "<suppressed>");
		else {
			print_field(buffer->tracking.payload, "<unavailable>");

			return diag("error tracking last-ip", offset, errcode);
		}
	} else
		print_field(buffer->tracking.payload, "%016" PRIx64, ip);

	return 0;
}


static int print_time(struct ptdump_buffer *buffer,
		      struct ptdump_tracking *tracking, uint64_t offset,
		      const struct ptdump_options *options)
{
	uint64_t tsc;
	int errcode;

	if (!tracking || !options)
		return diag("error printing time", offset, -pte_internal);

	print_field(buffer->tracking.id, "tsc");

	errcode = pt_time_query_tsc(&tsc, NULL, NULL, &tracking->time);
	if (errcode < 0) {
		switch (-errcode) {
		case pte_no_time:
			if (options->no_wall_clock)
				break;

			fallthrough;
		default:
			diag("error printing time", offset, errcode);
			print_field(buffer->tracking.payload, "<unavailable>");
			return errcode;
		}
	}

	if (options->show_time_as_delta) {
		uint64_t old_tsc;

		old_tsc = tracking->tsc;
		if (old_tsc <= tsc)
			print_field(buffer->tracking.payload, "+%" PRIx64,
				    tsc - old_tsc);
		else
			print_field(buffer->tracking.payload, "-%" PRIx64,
				    old_tsc - tsc);

		tracking->tsc = tsc;
	} else
		print_field(buffer->tracking.payload, "%016" PRIx64, tsc);

	return 0;
}

static int print_tcal(struct ptdump_buffer *buffer,
		      struct ptdump_tracking *tracking, uint64_t offset,
		      const struct ptdump_options *options)
{
	uint64_t fcr;
	double dfcr;
	int errcode;

	if (!tracking || !options)
		return diag("error printing time", offset, -pte_internal);

	print_field(buffer->tracking.id, "fcr");

	errcode = pt_tcal_fcr(&fcr, &tracking->tcal);
	if (errcode < 0) {
		print_field(buffer->tracking.payload, "<unavailable>");
		return diag("error printing time", offset, errcode);
	}

	/* We print fcr as double to account for the shift. */
	dfcr = (double) fcr;
	dfcr /= (double) (1ull << pt_tcal_fcr_shr);

	if (options->show_time_as_delta) {
		uint64_t old_fcr;
		double dold_fcr;

		old_fcr = tracking->fcr;

		/* We print fcr as double to account for the shift. */
		dold_fcr = (double) old_fcr;
		dold_fcr /= (double) (1ull << pt_tcal_fcr_shr);

		print_field(buffer->tracking.payload, "%+.3f",
			    dfcr - dold_fcr);

		tracking->fcr = fcr;
	} else
		print_field(buffer->tracking.payload, "%.3f", dfcr);

	return 0;
}

static int sb_track_time(struct ptdump_tracking *tracking,
			 const struct ptdump_options *options, uint64_t offset)
{
	uint64_t tsc;
	int errcode;

	if (!tracking || !options)
		return diag("time tracking error", offset, -pte_internal);

	errcode = pt_time_query_tsc(&tsc, NULL, NULL, &tracking->time);
	if ((errcode < 0) && (errcode != -pte_no_time))
		return diag("time tracking error", offset, errcode);

#if defined(FEATURE_SIDEBAND)
	errcode = pt_sb_dump(tracking->session, stdout, options->sb_dump_flags,
			     tsc);
	if (errcode < 0)
		return diag("sideband dump error", offset, errcode);
#endif
	return 0;
}

static int track_time(struct ptdump_buffer *buffer,
		      struct ptdump_tracking *tracking, uint64_t offset,
		      const struct ptdump_options *options)
{
	if (!tracking || !options)
		return diag("error tracking time", offset, -pte_internal);

	if (options->show_tcal && !buffer->skip_tcal)
		print_tcal(buffer, tracking, offset, options);

	if (options->show_time && !buffer->skip_time)
		print_time(buffer, tracking, offset, options);

	return sb_track_time(tracking, options, offset);
}

static int track_tsc(struct ptdump_buffer *buffer,
		     struct ptdump_tracking *tracking,  uint64_t offset,
		     const struct pt_packet_tsc *packet,
		     const struct ptdump_options *options,
		     const struct pt_config *config)
{
	int errcode;

	if (!buffer || !tracking || !options)
		return diag("error tracking time", offset, -pte_internal);

	if (!options->no_tcal) {
		errcode = tracking->in_header ?
			pt_tcal_header_tsc(&tracking->tcal, packet, config) :
			pt_tcal_update_tsc(&tracking->tcal, packet, config);
		if (errcode < 0)
			diag("error calibrating time", offset, errcode);
	}

	errcode = pt_time_update_tsc(&tracking->time, packet, config);
	if (errcode < 0)
		diag("error updating time", offset, errcode);

	return track_time(buffer, tracking, offset, options);
}

static int track_cbr(struct ptdump_buffer *buffer,
		     struct ptdump_tracking *tracking,  uint64_t offset,
		     const struct pt_packet_cbr *packet,
		     const struct ptdump_options *options,
		     const struct pt_config *config)
{
	int errcode;

	if (!buffer || !tracking || !options)
		return diag("error tracking time", offset, -pte_internal);

	if (!options->no_tcal) {
		errcode = tracking->in_header ?
			pt_tcal_header_cbr(&tracking->tcal, packet, config) :
			pt_tcal_update_cbr(&tracking->tcal, packet, config);
		if (errcode < 0)
			diag("error calibrating time", offset, errcode);
	}

	errcode = pt_time_update_cbr(&tracking->time, packet, config);
	if (errcode < 0)
		diag("error updating time", offset, errcode);

	/* There is no timing update at this packet. */
	buffer->skip_time = 1;

	return track_time(buffer, tracking, offset, options);
}

static int track_tma(struct ptdump_buffer *buffer,
		     struct ptdump_tracking *tracking,  uint64_t offset,
		     const struct pt_packet_tma *packet,
		     const struct ptdump_options *options,
		     const struct pt_config *config)
{
	int errcode;

	if (!buffer || !tracking || !options)
		return diag("error tracking time", offset, -pte_internal);

	if (!options->no_tcal) {
		errcode = pt_tcal_update_tma(&tracking->tcal, packet, config);
		if (errcode < 0)
			diag("error calibrating time", offset, errcode);
	}

	errcode = pt_time_update_tma(&tracking->time, packet, config);
	if (errcode < 0)
		diag("error updating time", offset, errcode);

	/* There is no calibration update at this packet. */
	buffer->skip_tcal = 1;

	return track_time(buffer, tracking, offset, options);
}

static int track_mtc(struct ptdump_buffer *buffer,
		     struct ptdump_tracking *tracking,  uint64_t offset,
		     const struct pt_packet_mtc *packet,
		     const struct ptdump_options *options,
		     const struct pt_config *config)
{
	int errcode;

	if (!buffer || !tracking || !options)
		return diag("error tracking time", offset, -pte_internal);

	if (!options->no_tcal) {
		errcode = pt_tcal_update_mtc(&tracking->tcal, packet, config);
		if (errcode < 0)
			diag("error calibrating time", offset, errcode);
	}

	errcode = pt_time_update_mtc(&tracking->time, packet, config);
	if (errcode < 0)
		diag("error updating time", offset, errcode);

	return track_time(buffer, tracking, offset, options);
}

static int track_cyc(struct ptdump_buffer *buffer,
		     struct ptdump_tracking *tracking,  uint64_t offset,
		     const struct pt_packet_cyc *packet,
		     const struct ptdump_options *options,
		     const struct pt_config *config)
{
	uint64_t fcr;
	int errcode;

	if (!buffer || !tracking || !options)
		return diag("error tracking time", offset, -pte_internal);

	/* Initialize to zero in case of calibration errors. */
	fcr = 0ull;

	if (!options->no_tcal) {
		errcode = pt_tcal_fcr(&fcr, &tracking->tcal);
		if (errcode < 0)
			diag("calibration error", offset, errcode);

		errcode = pt_tcal_update_cyc(&tracking->tcal, packet, config);
		if (errcode < 0)
			diag("error calibrating time", offset, errcode);
	}

	errcode = pt_time_update_cyc(&tracking->time, packet, config, fcr);
	if (errcode < 0)
		diag("error updating time", offset, errcode);
	else if (!fcr)
		diag("error updating time: no calibration", offset, 0);

	/* There is no calibration update at this packet. */
	buffer->skip_tcal = 1;

	return track_time(buffer, tracking, offset, options);
}

static uint64_t sext(uint64_t val, uint8_t sign)
{
	uint64_t signbit, mask;

	signbit = 1ull << (sign - 1);
	mask = ~0ull << sign;

	return val & signbit ? val | mask : val & ~mask;
}

static int print_ip_payload(struct ptdump_buffer *buffer, uint64_t offset,
			    const struct pt_packet_ip *packet)
{
	if (!buffer || !packet)
		return diag("error printing payload", offset, -pte_internal);

	size_t addr = 0;
	switch (packet->ipc) {
	case pt_ipc_suppressed:
		print_field(buffer->payload.standard, "%x: ????????????????",
			    pt_ipc_suppressed);
		return 0;

	case pt_ipc_update_16:
		print_field(buffer->payload.standard, "%x: ????????????%04"
			    PRIx64, pt_ipc_update_16, packet->ip);
		fix_upper_bits(packet->ip, 16);
		return 0;

	case pt_ipc_update_32:
		print_field(buffer->payload.standard, "%x: ????????%08"
			    PRIx64, pt_ipc_update_32, packet->ip);
		fix_upper_bits(packet->ip, 32);
		return 0;

	case pt_ipc_update_48:
		print_field(buffer->payload.standard, "%x: ????%012"
			    PRIx64, pt_ipc_update_48, packet->ip);
		fix_upper_bits(packet->ip, 48);
		return 0;

	case pt_ipc_sext_48:
		print_field(buffer->payload.standard, "%x: %016" PRIx64,
			    pt_ipc_sext_48, sext(packet->ip, 48));
		fix_upper_bits(sext(packet->ip, 48), 48);
		return 0;

	case pt_ipc_full:
		print_field(buffer->payload.standard, "%x: %016" PRIx64,
			    pt_ipc_full, packet->ip);
		fix_upper_bits(packet->ip, 64);
		return 0;
	}

	print_field(buffer->payload.standard, "%x: %016" PRIx64,
		    packet->ipc, packet->ip);
	fix_upper_bits(packet->ip, 64);
	return diag("bad ipc", offset, -pte_bad_packet);
}

static int print_tnt_payload(struct ptdump_buffer *buffer, uint64_t offset,
			     const struct pt_packet_tnt *packet)
{
	uint64_t tnt;
	uint8_t bits;
	char *begin, *end;

	if (!buffer || !packet)
		return diag("error printing payload", offset, -pte_internal);

	bits = packet->bit_size;
	tnt = packet->payload;

	begin = buffer->payload.extended;
	end = begin + bits;

	if (sizeof(buffer->payload.extended) < bits) {
		diag("truncating tnt payload", offset, 0);

		end = begin + sizeof(buffer->payload.extended);
	}

	for (; begin < end; ++begin, --bits)
		*begin = tnt & (1ull << (bits - 1)) ? '!' : '.';

	return 0;
}

static const char *print_exec_mode(const struct pt_packet_mode_exec *packet,
				   uint64_t offset)
{
	enum pt_exec_mode mode;

	mode = pt_get_exec_mode(packet);
	switch (mode) {
	case ptem_64bit:
		return "64-bit";

	case ptem_32bit:
		return "32-bit";

	case ptem_16bit:
		return "16-bit";

	case ptem_unknown:
		return "unknown";
	}

	diag("bad exec mode", offset, -pte_bad_packet);
	return "invalid";
}

static const char *print_pwrx_wr(const struct pt_packet_pwrx *packet)
{
	const char *wr;

	if (!packet)
		return "err";

	wr = NULL;
	if (packet->interrupt)
		wr = "int";

	if (packet->store) {
		if (wr)
			return NULL;
		wr = " st";
	}

	if (packet->autonomous) {
		if (wr)
			return NULL;
		wr = " hw";
	}

	if (!wr)
		wr = "bad";

	return wr;
}

static int print_packet(struct ptdump_buffer *buffer, uint64_t offset,
			const struct pt_packet *packet,
			struct ptdump_tracking *tracking,
			const struct ptdump_options *options,
			const struct pt_config *config)
{
	if (!buffer || !packet || !tracking || !options)
		return diag("error printing packet", offset, -pte_internal);

	switch (packet->type) {
	case ppt_unknown:
		print_field(buffer->opcode, "<unknown>");
		return 0;

	case ppt_invalid:
		print_field(buffer->opcode, "<invalid>");
		return 0;

	case ppt_psb:
		print_field(buffer->opcode, "psb");

		if (options->track_time) {
			int errcode;

			errcode = pt_tcal_update_psb(&tracking->tcal, config);
			if (errcode < 0)
				diag("error calibrating time", offset, errcode);
		}

		tracking->in_header = 1;
		return 0;

	case ppt_psbend:
		print_field(buffer->opcode, "psbend");

		tracking->in_header = 0;
		return 0;

	case ppt_pad:
		print_field(buffer->opcode, "pad");

		if (options->no_pad)
			buffer->skip = 1;
		return 0;

	case ppt_ovf:
		print_field(buffer->opcode, "ovf");

		if (options->track_time) {
			if (options->keep_tcal_on_ovf) {
				int errcode;

				errcode = pt_tcal_update_ovf(&tracking->tcal,
							     config);
				if (errcode < 0)
					diag("error calibrating time",
					     offset, errcode);
			} else
				pt_tcal_init(&tracking->tcal);
		}

		return 0;

	case ppt_stop:
		print_field(buffer->opcode, "stop");
		return 0;

	case ppt_fup:
		print_field(buffer->opcode, "fup");
		print_ip_payload(buffer, offset, &packet->payload.ip);

		if (options->show_last_ip)
			track_last_ip(buffer, &tracking->last_ip, offset,
				      &packet->payload.ip, options, config);
		return 0;

	case ppt_tip:
		print_field(buffer->opcode, "tip");
		print_ip_payload(buffer, offset, &packet->payload.ip);

		if (options->show_last_ip)
			track_last_ip(buffer, &tracking->last_ip, offset,
				      &packet->payload.ip, options, config);
		return 0;

	case ppt_tip_pge:
		print_field(buffer->opcode, "tip.pge");
		print_ip_payload(buffer, offset, &packet->payload.ip);

		if (options->show_last_ip)
			track_last_ip(buffer, &tracking->last_ip, offset,
				      &packet->payload.ip, options, config);
		return 0;

	case ppt_tip_pgd:
		print_field(buffer->opcode, "tip.pgd");
		print_ip_payload(buffer, offset, &packet->payload.ip);

		if (options->show_last_ip)
			track_last_ip(buffer, &tracking->last_ip, offset,
				      &packet->payload.ip, options, config);
		return 0;

	case ppt_pip:
		print_field(buffer->opcode, "pip");
		print_field(buffer->payload.standard, "%" PRIx64 "%s",
			    packet->payload.pip.cr3,
			    packet->payload.pip.nr ? ", nr" : "");

		print_field(buffer->tracking.id, "cr3");
		print_field(buffer->tracking.payload, "%016" PRIx64,
			    packet->payload.pip.cr3);
		return 0;

	case ppt_vmcs:
		print_field(buffer->opcode, "vmcs");
		print_field(buffer->payload.standard, "%" PRIx64,
			    packet->payload.vmcs.base);

		print_field(buffer->tracking.id, "vmcs");
		print_field(buffer->tracking.payload, "%016" PRIx64,
			    packet->payload.vmcs.base);
		return 0;

	case ppt_tnt_8:
		print_field(buffer->opcode, "tnt.8");
		return print_tnt_payload(buffer, offset, &packet->payload.tnt);

	case ppt_tnt_64:
		print_field(buffer->opcode, "tnt.64");
		return print_tnt_payload(buffer, offset, &packet->payload.tnt);

	case ppt_mode: {
		const struct pt_packet_mode *mode;

		mode = &packet->payload.mode;
		switch (mode->leaf) {
		case pt_mol_exec: {
			const char *csd, *csl, *sep;

			csd = mode->bits.exec.csd ? "cs.d" : "";
			csl = mode->bits.exec.csl ? "cs.l" : "";

			sep = csd[0] && csl[0] ? ", " : "";

			print_field(buffer->opcode, "mode.exec");
			print_field(buffer->payload.standard, "%s%s%s",
				    csd, sep, csl);

			if (options->show_exec_mode) {
				const char *em;

				em = print_exec_mode(&mode->bits.exec, offset);
				print_field(buffer->tracking.id, "em");
				print_field(buffer->tracking.payload, "%s", em);
			}
		}
			return 0;

		case pt_mol_tsx: {
			const char *intx, *abrt, *sep;

			intx = mode->bits.tsx.intx ? "intx" : "";
			abrt = mode->bits.tsx.abrt ? "abrt" : "";

			sep = intx[0] && abrt[0] ? ", " : "";

			print_field(buffer->opcode, "mode.tsx");
			print_field(buffer->payload.standard, "%s%s%s",
				    intx, sep, abrt);
		}
			return 0;
		}

		print_field(buffer->opcode, "mode");
		print_field(buffer->payload.standard, "leaf: %x", mode->leaf);

		return diag("unknown mode leaf", offset, 0);
	}

	case ppt_tsc:
		print_field(buffer->opcode, "tsc");
		print_field(buffer->payload.standard, "%" PRIx64,
			    packet->payload.tsc.tsc);

		if (options->track_time)
			track_tsc(buffer, tracking, offset,
				  &packet->payload.tsc, options, config);

		if (options->no_timing)
			buffer->skip = 1;

		return 0;

	case ppt_cbr:
		print_field(buffer->opcode, "cbr");
		print_field(buffer->payload.standard, "%x",
			    packet->payload.cbr.ratio);

		if (options->track_time)
			track_cbr(buffer, tracking, offset,
				  &packet->payload.cbr, options, config);

		if (options->no_timing)
			buffer->skip = 1;

		return 0;

	case ppt_tma:
		print_field(buffer->opcode, "tma");
		print_field(buffer->payload.standard, "%x, %x",
			    packet->payload.tma.ctc, packet->payload.tma.fc);

		if (options->track_time)
			track_tma(buffer, tracking, offset,
				  &packet->payload.tma, options, config);

		if (options->no_timing)
			buffer->skip = 1;

		return 0;

	case ppt_mtc:
		print_field(buffer->opcode, "mtc");
		print_field(buffer->payload.standard, "%x",
			    packet->payload.mtc.ctc);

		if (options->track_time)
			track_mtc(buffer, tracking, offset,
				  &packet->payload.mtc, options, config);

		if (options->no_timing)
			buffer->skip = 1;

		return 0;

	case ppt_cyc:
		print_field(buffer->opcode, "cyc");
		print_field(buffer->payload.standard, "%" PRIx64,
			    packet->payload.cyc.value);

		if (options->track_time && !options->no_cyc)
			track_cyc(buffer, tracking, offset,
				  &packet->payload.cyc, options, config);

		if (options->no_timing || options->no_cyc)
			buffer->skip = 1;

		return 0;

	case ppt_mnt:
		print_field(buffer->opcode, "mnt");
		print_field(buffer->payload.standard, "%" PRIx64,
			    packet->payload.mnt.payload);
		return 0;

	case ppt_exstop:
		print_field(buffer->opcode, "exstop");
		print_field(buffer->payload.standard, "%s",
			    packet->payload.exstop.ip ? "ip" : "");
		return 0;

	case ppt_mwait:
		print_field(buffer->opcode, "mwait");
		print_field(buffer->payload.standard, "%08x, %08x",
			    packet->payload.mwait.hints,
			    packet->payload.mwait.ext);
		return 0;

	case ppt_pwre:
		print_field(buffer->opcode, "pwre");
		print_field(buffer->payload.standard, "c%u.%u%s",
			    (packet->payload.pwre.state + 1) & 0xf,
			    (packet->payload.pwre.sub_state + 1) & 0xf,
			    packet->payload.pwre.hw ? ", hw" : "");
		return 0;

	case ppt_pwrx: {
		const char *wr;

		wr = print_pwrx_wr(&packet->payload.pwrx);
		if (!wr)
			wr = "bad";

		print_field(buffer->opcode, "pwrx");
		print_field(buffer->payload.standard, "%s: c%u, c%u", wr,
			    (packet->payload.pwrx.last + 1) & 0xf,
			    (packet->payload.pwrx.deepest + 1) & 0xf);
		return 0;
	}

	case ppt_ptw:
		print_field(buffer->opcode, "ptw");
		print_field(buffer->payload.standard, "%x: %" PRIx64 "%s",
			    packet->payload.ptw.plc,
			    packet->payload.ptw.payload,
			    packet->payload.ptw.ip ? ", ip" : "");

		return 0;
	}

	return diag("unknown packet", offset, -pte_bad_opc);
}

static int dump_one_packet(uint64_t offset, const struct pt_packet *packet,
			   struct ptdump_tracking *tracking,
			   const struct ptdump_options *options,
			   const struct pt_config *config)
{
	struct ptdump_buffer buffer;
	int errcode;

	memset(&buffer, 0, sizeof(buffer));

	print_field(buffer.offset, "%016" PRIx64, offset);

	if (options->show_raw_bytes) {
		errcode = print_raw(&buffer, offset, packet, config);
		if (errcode < 0)
			return errcode;
	}

	errcode = print_packet(&buffer, offset, packet, tracking, options,
			       config);
	if (errcode < 0)
		return errcode;

	return print_buffer(&buffer, offset, options);
}

static int dump_packets(struct pt_packet_decoder *decoder,
			struct ptdump_tracking *tracking,
			const struct ptdump_options *options,
			const struct pt_config *config)
{
	uint64_t offset;
	int errcode;

	offset = 0ull;
	for (;;) {
		struct pt_packet packet;

		errcode = pt_pkt_get_offset(decoder, &offset);
		if (errcode < 0)
			return diag("error getting offset", offset, errcode);

		errcode = pt_pkt_next(decoder, &packet, sizeof(packet));
		if (errcode < 0) {
			if (errcode == -pte_eos)
				return 0;

			return diag("error decoding packet", offset, errcode);
		}

		errcode = dump_one_packet(offset, &packet, tracking, options,
					  config);
		if (errcode < 0)
			return errcode;
	}
}

static int dump_sync(struct pt_packet_decoder *decoder,
		     struct ptdump_tracking *tracking,
		     const struct ptdump_options *options,
		     const struct pt_config *config)
{
	int errcode;

	if (!options)
		return diag("setup error", 0ull, -pte_internal);

	if (options->no_sync) {
		errcode = pt_pkt_sync_set(decoder, 0ull);
		if (errcode < 0)
			return diag("sync error", 0ull, errcode);
	} else {
		errcode = pt_pkt_sync_forward(decoder);
		if (errcode < 0) {
			if (errcode == -pte_eos)
				return 0;

			return diag("sync error", 0ull, errcode);
		}
	}

	for (;;) {
		errcode = dump_packets(decoder, tracking, options, config);
		if (!errcode)
			break;

		errcode = pt_pkt_sync_forward(decoder);
		if (errcode < 0) {
			if (errcode == -pte_eos)
				return 0;

			return diag("sync error", 0ull, errcode);
		}

		ptdump_tracking_reset(tracking);
	}

	return errcode;
}

static int dump(struct ptdump_tracking *tracking,
		const struct pt_config *config,
		const struct ptdump_options *options)
{
	struct pt_packet_decoder *decoder;
	int errcode;

	decoder = pt_pkt_alloc_decoder(config);
	if (!decoder)
		return diag("failed to allocate decoder", 0ull, 0);

	errcode = dump_sync(decoder, tracking, options, config);

	pt_pkt_free_decoder(decoder);

	if (errcode < 0)
		return errcode;

#if defined(FEATURE_SIDEBAND)
	errcode = pt_sb_dump(tracking->session, stdout, options->sb_dump_flags,
			     UINT64_MAX);
	if (errcode < 0)
		return diag("sideband dump error", UINT64_MAX, errcode);
#endif

	return 0;
}


static int get_arg_uint64(uint64_t *value, const char *option, const char *arg,
			  const char *prog)
{
	char *rest;

	if (!value || !option || !prog) {
		fprintf(stderr, "%s: internal error.\n", prog ? prog : "?");
		return 0;
	}

	if (!arg || arg[0] == 0 || (arg[0] == '-' && arg[1] == '-')) {
		fprintf(stderr, "%s: %s: missing argument.\n", prog, option);
		return 0;
	}

	errno = 0;
	*value = strtoull(arg, &rest, 0);
	if (errno || *rest) {
		fprintf(stderr, "%s: %s: bad argument: %s.\n", prog, option,
			arg);
		return 0;
	}

	return 1;
}

static int get_arg_uint32(uint32_t *value, const char *option, const char *arg,
			  const char *prog)
{
	uint64_t val;

	if (!get_arg_uint64(&val, option, arg, prog))
		return 0;

	if (val > UINT32_MAX) {
		fprintf(stderr, "%s: %s: value too big: %s.\n", prog, option,
			arg);
		return 0;
	}

	*value = (uint32_t) val;

	return 1;
}

static int get_arg_uint8(uint8_t *value, const char *option, const char *arg,
			 const char *prog)
{
	uint64_t val;

	if (!get_arg_uint64(&val, option, arg, prog))
		return 0;

	if (val > UINT8_MAX) {
		fprintf(stderr, "%s: %s: value too big: %s.\n", prog, option,
			arg);
		return 0;
	}

	*value = (uint8_t) val;

	return 1;
}

static int process_args(struct ptdump_options *options)
{
	options->no_pad = 1;
	options->no_timing = 1;
	options->no_cyc = 1;
	options->show_last_ip = 1;
	return 0;
}

int do_main(char *ptfile)
{
	struct ptdump_tracking tracking;
	struct ptdump_options options;
	struct pt_config config;
	int errcode;

	memset(&options, 0, sizeof(options));
	options.show_offset = 1;

	memset(&config, 0, sizeof(config));
	pt_config_init(&config);

	ptdump_tracking_init(&tracking);

	ip_table_size = 100;
	ip_table_ctr = 0;
	ip_table = calloc(ip_table_size, sizeof(size_t));

	errcode = process_args(&options);
	if (errcode != 0) {
		if (errcode > 0)
			errcode = 0;
		goto out;
	}

	if (!ptfile) {
		errcode = no_file_error("ptdump");
		goto out;
	}

	errcode = load_pt(&config, ptfile, 0, 0, "ptdump");
	if (errcode < 0)
		goto out;

	errcode = dump(&tracking, &config, &options);

out:
	free(ip_table);
	free(config.begin);
	ptdump_tracking_fini(&tracking);

	return -errcode;
}
