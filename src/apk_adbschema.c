#include "adb.h"
#include "apk_adb.h"
#include "apk_print.h"
#include "apk_version.h"

#define APK_VERSION_CONFLICT 16

static apk_blob_t string_tostring(struct adb *db, adb_val_t val, char *buf, size_t bufsz)
{
	return adb_r_blob(db, val);
}

static struct adb_scalar_schema scalar_string = {
	.kind = ADB_KIND_BLOB,
	.tostring = string_tostring,
};

static apk_blob_t hexblob_tostring(struct adb *db, adb_val_t val, char *buf, size_t bufsz)
{
	apk_blob_t b = adb_r_blob(db, val), to = APK_BLOB_PTR_LEN(buf, bufsz);

	if (APK_BLOB_IS_NULL(b)) return b;

	apk_blob_push_hexdump(&to, b);
	if (!APK_BLOB_IS_NULL(to))
		return APK_BLOB_PTR_PTR(buf, to.ptr-1);

	return APK_BLOB_PTR_LEN(buf, snprintf(buf, bufsz, "(%ld bytes)", b.len));
}

static struct adb_scalar_schema scalar_hexblob = {
	.kind = ADB_KIND_BLOB,
	.tostring = hexblob_tostring,
};

static apk_blob_t int_tostring(struct adb *db, adb_val_t val, char *buf, size_t bufsz)
{
	return APK_BLOB_PTR_LEN(buf, snprintf(buf, bufsz, "%u", adb_r_int(db, val)));
}

static struct adb_scalar_schema scalar_int = {
	.kind = ADB_KIND_INT,
	.tostring = int_tostring,
};

static apk_blob_t oct_tostring(struct adb *db, adb_val_t val, char *buf, size_t bufsz)
{
	return APK_BLOB_PTR_LEN(buf, snprintf(buf, bufsz, "%o", adb_r_int(db, val)));
}

static struct adb_scalar_schema scalar_oct = {
	.kind = ADB_KIND_INT,
	.tostring = oct_tostring,
};

static apk_blob_t hsize_tostring(struct adb *db, adb_val_t val, char *buf, size_t bufsz)
{
	off_t v = adb_r_int(db, val);
	const char *unit = apk_get_human_size(v, &v);

	return APK_BLOB_PTR_LEN(buf, snprintf(buf, bufsz, "%jd %s", (intmax_t)v, unit));
}

static struct adb_scalar_schema scalar_hsize = {
	.kind = ADB_KIND_INT,
	.tostring = hsize_tostring,
};

static apk_blob_t dependency_tostring(struct adb *db, adb_val_t val, char *buf, size_t bufsz)
{
	struct adb_obj o;
	apk_blob_t name, ver;
	unsigned int mask;

	adb_r_obj(db, val, &o, &schema_dependency);
	name = adb_ro_blob(&o, ADBI_DEP_NAME);
	ver  = adb_ro_blob(&o, ADBI_DEP_VERSION);

	if (APK_BLOB_IS_NULL(name)) return APK_BLOB_NULL;
	if (APK_BLOB_IS_NULL(ver)) return name;

	mask = adb_ro_int(&o, ADBI_DEP_MATCH) ?: APK_VERSION_EQUAL;
	return APK_BLOB_PTR_LEN(buf,
		snprintf(buf, bufsz, "%s"BLOB_FMT"%s"BLOB_FMT,
			(mask & APK_VERSION_CONFLICT) ? "!" : "",
			BLOB_PRINTF(name),
			apk_version_op_string(mask & ~APK_VERSION_CONFLICT),
			BLOB_PRINTF(ver)));
}

const struct adb_object_schema schema_dependency = {
	.kind = ADB_KIND_OBJECT,
	.num_fields = ADBI_DEP_MAX,
	.tostring = dependency_tostring,
	.fields = {
		ADB_FIELD(ADBI_DEP_NAME,	"name",		scalar_string),
		ADB_FIELD(ADBI_DEP_VERSION,	"version",	scalar_string),
		ADB_FIELD(ADBI_DEP_MATCH,	"match",	scalar_int),
	},
};

const struct adb_object_schema schema_dependency_array = {
	.kind = ADB_KIND_ARRAY,
	.num_fields = APK_MAX_PKG_DEPENDENCIES,
	.fields = ADB_ARRAY_ITEM(schema_dependency),
};

static int pkginfo_cmp(struct adb_obj *o1, struct adb_obj *o2)
{
	int r;
	r = apk_blob_sort(
		adb_ro_blob(o1, ADBI_PI_NAME),
		adb_ro_blob(o2, ADBI_PI_NAME));
	if (r) return r;

	r = apk_version_compare_blob(
		adb_ro_blob(o1, ADBI_PI_VERSION),
		adb_ro_blob(o2, ADBI_PI_VERSION));
	switch (r) {
	case APK_VERSION_LESS: return -1;
	case APK_VERSION_GREATER: return 1;
	}
	return 0;
}

const struct adb_object_schema schema_pkginfo = {
	.kind = ADB_KIND_OBJECT,
	.num_fields = ADBI_PI_MAX,
	.compare = pkginfo_cmp,
	.fields = {
		ADB_FIELD(ADBI_PI_NAME,		"name",		scalar_string),
		ADB_FIELD(ADBI_PI_VERSION,	"version",	scalar_string),
		ADB_FIELD(ADBI_PI_UNIQUE_ID,	"unique-id",	scalar_int),
		ADB_FIELD(ADBI_PI_DESCRIPTION,	"description",	scalar_string),
		ADB_FIELD(ADBI_PI_ARCH,		"arch",		scalar_string),
		ADB_FIELD(ADBI_PI_LICENSE,	"license",	scalar_string),
		ADB_FIELD(ADBI_PI_ORIGIN,	"origin",	scalar_string),
		ADB_FIELD(ADBI_PI_MAINTAINER,	"maintainer",	scalar_string),
		ADB_FIELD(ADBI_PI_URL,		"url",		scalar_string),
		ADB_FIELD(ADBI_PI_REPO_COMMIT,	"repo-commit",	scalar_hexblob),
		ADB_FIELD(ADBI_PI_BUILD_TIME,	"build-time",	scalar_int),
		ADB_FIELD(ADBI_PI_INSTALLED_SIZE,"installed-size",scalar_hsize),
		ADB_FIELD(ADBI_PI_FILE_SIZE,	"file-size",	scalar_hsize),
		ADB_FIELD(ADBI_PI_PRIORITY,	"priority",	scalar_int),
		ADB_FIELD(ADBI_PI_DEPENDS,	"depends",	schema_dependency_array),
		ADB_FIELD(ADBI_PI_PROVIDES,	"provides",	schema_dependency_array),
		ADB_FIELD(ADBI_PI_REPLACES,	"replaces",	schema_dependency_array),
		ADB_FIELD(ADBI_PI_INSTALL_IF,	"install-if",	schema_dependency_array),
		ADB_FIELD(ADBI_PI_RECOMMENDS,	"recommends",	schema_dependency_array),
	},
};

const struct adb_object_schema schema_pkginfo_array = {
	.kind = ADB_KIND_ARRAY,
	.num_fields = APK_MAX_INDEX_PACKAGES,
	.pre_commit = adb_wa_sort,
	.fields = ADB_ARRAY_ITEM(schema_pkginfo),
};

const struct adb_object_schema schema_index = {
	.kind = ADB_KIND_OBJECT,
	.num_fields = ADBI_NDX_MAX,
	.fields = {
		ADB_FIELD(ADBI_NDX_DESCRIPTION,	"description",	scalar_string),
		ADB_FIELD(ADBI_NDX_PACKAGES,	"packages",	schema_pkginfo_array),
	},
};

static uint32_t file_get_default_int(unsigned i)
{
	switch (i) {
	case ADBI_FI_UID:
	case ADBI_FI_GID:
		return 0;
	case ADBI_FI_MODE:
		return 0644;
	}
	return -1;
}

static int file_cmp(struct adb_obj *o1, struct adb_obj *o2)
{
	return apk_blob_sort(
		adb_ro_blob(o1, ADBI_FI_NAME),
		adb_ro_blob(o2, ADBI_FI_NAME));
}

const struct adb_object_schema schema_file = {
	.kind = ADB_KIND_OBJECT,
	.num_fields = ADBI_FI_MAX,
	.get_default_int = file_get_default_int,
	.compare = file_cmp,
	.fields = {
		ADB_FIELD(ADBI_FI_NAME,		"name",		scalar_string),
		ADB_FIELD(ADBI_FI_HASHES,	"hash",		scalar_hexblob),
		ADB_FIELD(ADBI_FI_UID,		"uid",		scalar_int),
		ADB_FIELD(ADBI_FI_GID,		"gid",		scalar_int),
		ADB_FIELD(ADBI_FI_MODE,		"mode",		scalar_oct),
		ADB_FIELD(ADBI_FI_XATTRS,	"xattr",	scalar_hexblob),
	},
};

const struct adb_object_schema schema_file_array = {
	.kind = ADB_KIND_ARRAY,
	.pre_commit = adb_wa_sort,
	.num_fields = APK_MAX_MANIFEST_FILES,
	.fields = ADB_ARRAY_ITEM(schema_file),
};

static uint32_t path_get_default_int(unsigned i)
{
	switch (i) {
	case ADBI_FI_UID:
	case ADBI_FI_GID:
		return 0;
	case ADBI_FI_MODE:
		return 0755;
	}
	return -1;
}

const struct adb_object_schema schema_path = {
	.kind = ADB_KIND_OBJECT,
	.num_fields = ADBI_FI_MAX,
	.get_default_int = path_get_default_int,
	.compare = file_cmp,
	.fields = {
		ADB_FIELD(ADBI_FI_NAME,		"name",		scalar_string),
		ADB_FIELD(ADBI_FI_FILES,	"files",	schema_file_array),
		ADB_FIELD(ADBI_FI_UID,		"uid",		scalar_int),
		ADB_FIELD(ADBI_FI_GID,		"gid",		scalar_int),
		ADB_FIELD(ADBI_FI_MODE,		"mode",		scalar_oct),
		ADB_FIELD(ADBI_FI_XATTRS,	"xattr",	scalar_hexblob),
	},
};

const struct adb_object_schema schema_path_array = {
	.kind = ADB_KIND_ARRAY,
	.pre_commit = adb_wa_sort,
	.num_fields = APK_MAX_MANIFEST_PATHS,
	.fields = ADB_ARRAY_ITEM(schema_path),
};

const struct adb_object_schema schema_package = {
	.kind = ADB_KIND_OBJECT,
	.num_fields = ADBI_PKG_MAX,
	.fields = {
		ADB_FIELD(ADBI_PKG_PKGINFO,	"info",		schema_pkginfo),
		ADB_FIELD(ADBI_PKG_PATHS,	"paths",	schema_path_array),
	},
};

const struct adb_adb_schema schema_package_adb = {
	.kind = ADB_KIND_ADB,
	.schema_id = ADB_SCHEMA_PACKAGE,
};

const struct adb_object_schema schema_package_adb_array = {
	.kind = ADB_KIND_ARRAY,
	.num_fields = APK_MAX_INDEX_PACKAGES,
	.fields = ADB_ARRAY_ITEM(schema_package_adb),
};

const struct adb_object_schema schema_idb = {
	.kind = ADB_KIND_OBJECT,
	.num_fields = ADBI_IDB_MAX,
	.fields = {
		ADB_FIELD(ADBI_IDB_PACKAGES,	"packages",	schema_package_adb_array),
	},
};
