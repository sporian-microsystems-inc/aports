/* app_mkndx.c - Alpine Package Keeper (APK)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2020 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation. See http://www.gnu.org/ for details.
 */

#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <assert.h>
#include <unistd.h>
#include <sys/stat.h>

#include "apk_adb.h"
#include "apk_applet.h"
#include "apk_database.h"
#include "apk_print.h"

struct mkndx_ctx {
	const char *index;
	const char *output;
	const char *description;
	apk_blob_t rewrite_arch;

	apk_blob_t r;
	struct adb db;
	struct adb_obj pkgs;
	time_t index_mtime;

	struct apk_sign_ctx sctx;
	size_t file_size;
};

static int option_parse_applet(void *ctx, struct apk_db_options *dbopts, int optch, const char *optarg)
{
	struct mkndx_ctx *ictx = ctx;

	switch (optch) {
	case 'x':
		ictx->index = optarg;
		break;
	case 'o':
		ictx->output = optarg;
		break;
	case 'd':
		ictx->description = optarg;
		break;
	case 0x10000:
		ictx->rewrite_arch = APK_BLOB_STR(optarg);
		break;
	default:
		return -ENOTSUP;
	}
	return 0;
}

static const struct apk_option options_applet[] = {
	{ 'o', "output", required_argument, "FILE" },
	{ 'x', "index", required_argument, "INDEX" },
	{ 'd', "description", required_argument, "TEXT" },
	{ 0x10000, "rewrite-arch", required_argument, "ARCH" },
};

static const struct apk_option_group optgroup_applet = {
	.name = "Index (v3)",
	.options = options_applet,
	.num_options = ARRAY_SIZE(options_applet),
	.parse = option_parse_applet,
};

struct field {
	apk_blob_t str;
	unsigned int ndx;
};
#define FIELD(s, n) { .str = APK_BLOB_STRLIT(s), .ndx = n }

static int cmpfield(const void *pa, const void *pb)
{
	const struct field *a = pa, *b = pb;
	return apk_blob_sort(a->str, b->str);
}

static adb_val_t mkndx_read_v2_pkginfo(struct adb *db, struct apk_istream *is, size_t file_size, struct apk_sign_ctx *sctx, apk_blob_t rewrite_arch)
{
	static struct field fields[]  = {
		FIELD("arch",			ADBI_PI_ARCH),
		FIELD("builddate",		ADBI_PI_BUILD_TIME),
		FIELD("commit",			ADBI_PI_REPO_COMMIT),
		FIELD("datahash",		0),
		FIELD("depend",			ADBI_PI_DEPENDS),
		FIELD("install_if",		ADBI_PI_INSTALL_IF),
		FIELD("license",		ADBI_PI_LICENSE),
		FIELD("maintainer",		ADBI_PI_MAINTAINER),
		FIELD("origin",			ADBI_PI_ORIGIN),
		FIELD("packager",		0),
		FIELD("pkgdesc",		ADBI_PI_DESCRIPTION),
		FIELD("pkgname",		ADBI_PI_NAME),
		FIELD("pkgver", 		ADBI_PI_VERSION),
		FIELD("provider_priority",	0),
		FIELD("provides",		ADBI_PI_PROVIDES),
		FIELD("replaces",		ADBI_PI_REPLACES),
		FIELD("replaces_priority",	ADBI_PI_PRIORITY),
		FIELD("size",			ADBI_PI_INSTALLED_SIZE),
		FIELD("triggers",		0),
		FIELD("url",			ADBI_PI_URL),
	};
	struct field *f, key;
	struct adb_obj pkginfo, deps[3];
	apk_blob_t line, l, r, token = APK_BLOB_STR("\n");
	int e = 0, i = 0;

	adb_wo_alloca(&pkginfo, &schema_pkginfo, db);
	adb_wo_alloca(&deps[0], &schema_dependency_array, db);
	adb_wo_alloca(&deps[1], &schema_dependency_array, db);
	adb_wo_alloca(&deps[2], &schema_dependency_array, db);

	while (!APK_BLOB_IS_NULL(line = apk_istream_get_delim(is, token))) {
		if (sctx) apk_sign_ctx_parse_pkginfo_line(sctx, line);
		if (line.len < 1 || line.ptr[0] == '#') continue;
		if (!apk_blob_split(line, APK_BLOB_STR(" = "), &l, &r)) continue;

		key.str = l;
		f = bsearch(&key, fields, ARRAY_SIZE(fields), sizeof(fields[0]), cmpfield);
		if (!f || f->ndx == 0) continue;

		if (adb_ro_val(&pkginfo, f->ndx) != ADB_NULL) {
			/* Workaround abuild bug that emitted multiple license lines */
			if (f->ndx == ADBI_PI_LICENSE) continue;
			 e = ADB_ERROR(EAPKFORMAT);
			 continue;
		}

		switch (f->ndx) {
		case ADBI_PI_ARCH:
			if (!APK_BLOB_IS_NULL(rewrite_arch)) r = rewrite_arch;
			break;
		case ADBI_PI_DEPENDS:
			i = 0;
			goto parse_deps;
		case ADBI_PI_PROVIDES:
			i = 1;
			goto parse_deps;
		case ADBI_PI_REPLACES:
			i = 2;
		parse_deps:
			while (!e && r.len) {
				if (!adb_wa_append(&deps[i], adb_w_dependency(db, &r)))
					e = EAPKFORMAT;
			}
			continue;
		}
		adb_wo_val(&pkginfo, f->ndx, adb_w_pkginfo(db, f->ndx, &r));
	}
	if (e) return ADB_ERROR(e);

	adb_wo_arr(&pkginfo, ADBI_PI_DEPENDS, &deps[0]);
	adb_wo_arr(&pkginfo, ADBI_PI_PROVIDES, &deps[1]);
	adb_wo_arr(&pkginfo, ADBI_PI_REPLACES, &deps[2]);
	adb_wo_int(&pkginfo, ADBI_PI_FILE_SIZE, file_size);

	return adb_w_obj(&pkginfo);
}

static int mkndx_parse_v2_tar(void *pctx, const struct apk_file_info *ae, struct apk_istream *is)
{
	struct mkndx_ctx *ctx = pctx;
	adb_val_t o;
	int r;

	r = apk_sign_ctx_process_file(&ctx->sctx, ae, is);
	if (r <= 0) return r;
	if (ctx->sctx.control_verified) return -ECANCELED;
	if (!ctx->sctx.control_started || ctx->sctx.data_started) return 0;

	if (strcmp(ae->name, ".PKGINFO") == 0) {
		o = mkndx_read_v2_pkginfo(&ctx->db, is, ctx->file_size, &ctx->sctx, ctx->rewrite_arch);
		if (ADB_IS_ERROR(o)) return -ADB_VAL_VALUE(o);
		if (!o || !adb_wa_append(&ctx->pkgs, o))
			return -EAPKFORMAT;
	}

	return 0;
}

static int mkndx_main(void *pctx, struct apk_database *db, struct apk_string_array *args)
{
	struct adb odb, tmpdb;
	struct adb_obj oroot, opkgs, ndx, tmpl;
	struct apk_file_info fi;
	adb_val_t match;
	int r, found, errors = 0, newpkgs = 0, numpkgs;
	struct mkndx_ctx *ctx = pctx;
	char **parg;
	time_t index_mtime = 0;

	if (ctx->output == NULL) {
		apk_error("Please specify --output FILE");
		return -1;
	}

	adb_w_init_tmp(&tmpdb, 200);
	adb_wo_alloca(&tmpl, &schema_pkginfo, &tmpdb);

	adb_w_init_alloca(&ctx->db, ADB_SCHEMA_INDEX, 1000);
	adb_wo_alloca(&ndx, &schema_index, &ctx->db);
	adb_wo_alloca(&ctx->pkgs, &schema_pkginfo_array, &ctx->db);

	if (ctx->index) {
		apk_fileinfo_get(AT_FDCWD, ctx->index, APK_CHECKSUM_NONE, &fi);
		index_mtime = fi.mtime;

		r = adb_m_map(&odb, open(ctx->index, O_RDONLY), ADB_SCHEMA_INDEX, &db->trust);
		if (r) {
			apk_error("%s: %s", ctx->index, apk_error_str(r));
			return r;
		}
		adb_ro_obj(adb_r_rootobj(&odb, &oroot, &schema_index), ADBI_NDX_PACKAGES, &opkgs);
	}

	foreach_array_item(parg, args) {
		r = apk_fileinfo_get(AT_FDCWD, *parg, APK_CHECKSUM_NONE, &fi);
		if (r < 0) {
		err_pkg:
			apk_error("%s: %s", *parg, apk_error_str(r));
			errors++;
			continue;
		}
		ctx->file_size = fi.size;

		found = FALSE;
		if (index_mtime >= fi.mtime) {
			char *fname, *fend;
			apk_blob_t bname, bver;

			/* Check that it looks like a package name */
			fname = strrchr(*parg, '/');
			if (fname == NULL)
				fname = *parg;
			else
				fname++;
			fend = strstr(fname, ".apk");
			if (!fend) goto do_file;
			if (fend-fname > 10 && fend[-9] == '.') fend -= 9;
			if (apk_pkg_parse_name(APK_BLOB_PTR_PTR(fname, fend-1),
					       &bname, &bver) < 0)
				goto do_file;

			adb_wo_resetdb(&tmpl);
			adb_wo_blob(&tmpl, ADBI_PI_NAME, bname);
			adb_wo_blob(&tmpl, ADBI_PI_VERSION, bver);
			match = adb_w_obj(&tmpl);

			for (int i = 0; (i = adb_ra_find(&opkgs, i, &tmpdb, match)) > 0; ) {
				struct adb_obj pkg;

				adb_ro_obj(&opkgs, i, &pkg);
				if (apk_blob_compare(bname, adb_ro_blob(&pkg, ADBI_PI_NAME))) continue;
				if (apk_blob_compare(bver,  adb_ro_blob(&pkg, ADBI_PI_VERSION))) continue;
				if (fi.size != adb_ro_int(&pkg, ADBI_PI_FILE_SIZE)) continue;

				if (!adb_wa_append(&ctx->pkgs, adb_w_copy(&ctx->db, &odb, adb_ro_val(&opkgs, i))))
					errors++;

				found = TRUE;
				break;
			}
		}
		if (!found) {
		do_file:
			apk_sign_ctx_init(&ctx->sctx, APK_SIGN_VERIFY, NULL, db->keys_fd);
			r = apk_tar_parse(
				apk_istream_gunzip_mpart(apk_istream_from_file(AT_FDCWD, *parg), apk_sign_ctx_mpart_cb, &ctx->sctx),
				mkndx_parse_v2_tar, ctx, &db->id_cache);
			apk_sign_ctx_free(&ctx->sctx);
			if (r < 0 && r != -ECANCELED) goto err_pkg;
			newpkgs++;
		}
	}
	if (errors) {
		apk_error("%d errors, not creating index", errors);
		return -1;
	}

	numpkgs = adb_ra_num(&ctx->pkgs);
	adb_wo_blob(&ndx, ADBI_NDX_DESCRIPTION, APK_BLOB_STR(ctx->description));
	adb_wo_obj(&ndx, ADBI_NDX_PACKAGES, &ctx->pkgs);
	adb_w_rootobj(&ndx);

	r = adb_c_create(
		apk_ostream_to_file(AT_FDCWD, ctx->output, NULL, 0644),
		&ctx->db, &db->trust);

	adb_free(&ctx->db);
	adb_free(&odb);

	if (r == 0)
		apk_message("Index has %d packages (of which %d are new)",
			    numpkgs, newpkgs);
	else
		apk_error("Index creation failed: %s", apk_error_str(r));


#if 0
	apk_hash_foreach(&db->available.names, warn_if_no_providers, &counts);

	if (counts.unsatisfied != 0)
		apk_warning("Total of %d unsatisfiable package "
			    "names. Your repository may be broken.",
			    counts.unsatisfied);
#endif

	return r;
}

static struct apk_applet apk_mkndx = {
	.name = "mkndx",
	.arguments = "FILE...",
	.open_flags = APK_OPENF_READ | APK_OPENF_NO_STATE | APK_OPENF_NO_REPOS,
	.command_groups = APK_COMMAND_GROUP_REPO,
	.context_size = sizeof(struct mkndx_ctx),
	.optgroups = { &optgroup_global, &optgroup_signing, &optgroup_applet },
	.main = mkndx_main,
};

APK_DEFINE_APPLET(apk_mkndx);
