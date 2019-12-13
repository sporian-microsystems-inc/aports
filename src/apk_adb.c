#include "apk_adb.h"
#include "apk_version.h"

#define APK_VERSION_CONFLICT 16

adb_val_t adb_w_dependency(struct adb *db, apk_blob_t *b)
{
	extern const apk_spn_match_def apk_spn_dependency_comparer;
	extern const apk_spn_match_def apk_spn_dependency_separator;
	extern const apk_spn_match_def apk_spn_repotag_separator;
	struct adb_obj obj;
	apk_blob_t bdep, bname, bop, bver = APK_BLOB_NULL, btag;
	int mask = APK_DEPMASK_ANY;

	adb_wo_alloca(&obj, &schema_dependency, db);

	/* [!]name[<,<=,<~,=,~,>~,>=,>,><]ver */
	if (APK_BLOB_IS_NULL(*b))
		goto fail;

	/* grap one token */
	if (!apk_blob_cspn(*b, apk_spn_dependency_separator, &bdep, NULL))
		bdep = *b;
	b->ptr += bdep.len;
	b->len -= bdep.len;

	/* skip also all separator chars */
	if (!apk_blob_spn(*b, apk_spn_dependency_separator, NULL, b)) {
		b->ptr += b->len;
		b->len = 0;
	}

	/* parse the version */
	if (bdep.ptr[0] == '!') {
		bdep.ptr++;
		bdep.len--;
		mask |= APK_VERSION_CONFLICT;
	}

	if (apk_blob_cspn(bdep, apk_spn_dependency_comparer, &bname, &bop)) {
		int i;

		if (mask == 0)
			goto fail;
		if (!apk_blob_spn(bop, apk_spn_dependency_comparer, &bop, &bver))
			goto fail;

		mask = 0;
		for (i = 0; i < bop.len; i++) {
			switch (bop.ptr[i]) {
			case '<':
				mask |= APK_VERSION_LESS;
				break;
			case '>':
				mask |= APK_VERSION_GREATER;
				break;
			case '~':
				mask |= APK_VERSION_FUZZY|APK_VERSION_EQUAL;
				break;
			case '=':
				mask |= APK_VERSION_EQUAL;
				break;
			}
		}
		if ((mask & APK_DEPMASK_CHECKSUM) != APK_DEPMASK_CHECKSUM &&
		    !apk_version_validate(bver))
			goto fail;
	} else {
		bname = bdep;
		bop = APK_BLOB_NULL;
		bver = APK_BLOB_NULL;
	}

	if (apk_blob_cspn(bname, apk_spn_repotag_separator, &bname, &btag))
		; /* tag = repository tag */

	adb_wo_blob(&obj, ADBI_DEP_NAME, bname);
	if (mask != APK_DEPMASK_ANY) {
		adb_wo_blob(&obj, ADBI_DEP_VERSION, bver);
		if (mask != APK_VERSION_EQUAL)
			adb_wo_int(&obj, ADBI_DEP_MATCH, mask);
	}
	return adb_w_obj(&obj);

fail:
	return ADB_NULL;
}

adb_val_t adb_w_pkginfo(struct adb *db, unsigned int f, apk_blob_t *val)
{
	struct apk_checksum csum;
	struct adb_obj deps;

	switch (f) {
	case ADBI_PI_INSTALLED_SIZE:
	case ADBI_PI_FILE_SIZE:
	case ADBI_PI_BUILD_TIME:
	case ADBI_PI_PRIORITY:;
		uint32_t n = apk_blob_pull_uint(val, 10);
		if (!n) break;
		return adb_w_int(db, n);

	case ADBI_PI_DEPENDS:
	case ADBI_PI_INSTALL_IF:
	case ADBI_PI_PROVIDES:
	case ADBI_PI_REPLACES:
		/* array of package names */
		adb_wo_alloca(&deps, &schema_dependency_array, db);
		while (val->len)
			adb_wa_append(&deps, adb_w_dependency(db, val));
		return adb_w_arr(&deps);

	case ADBI_PI_UNIQUE_ID:
		if (!val->ptr || val->len < 4) break;
		apk_blob_pull_csum(val, &csum);
		return adb_w_int(db, get_unaligned32(csum.data) & ADB_VALUE_MASK);

	case ADBI_PI_REPO_COMMIT:
		if (val->len < 40) break;
		csum.type = 20;
		apk_blob_pull_hexdump(val, APK_BLOB_CSUM(csum));
		if (val->ptr) return adb_w_blob(db, APK_BLOB_CSUM(csum));
		break;
	default:
		if (!val->len) break;
		return adb_w_blob(db, *val);
	}

	return ADB_ERROR(EAPKFORMAT);
}

static struct adb *__db1, *__db2;

static int pkginfo_cmp(const void *p1, const void *p2)
{
	struct adb_obj o1, o2;
	int r;

	adb_r_obj(__db1, *(adb_val_t *)p1, &o1, &schema_pkginfo);
	adb_r_obj(__db2, *(adb_val_t *)p2, &o2, &schema_pkginfo);

	r = apk_blob_sort(
		adb_ro_blob(&o1, ADBI_PI_NAME),
		adb_ro_blob(&o2, ADBI_PI_NAME));
	if (r) return r;

	r = apk_version_compare_blob(
		adb_ro_blob(&o1, ADBI_PI_VERSION),
		adb_ro_blob(&o2, ADBI_PI_VERSION));
	switch (r) {
	case APK_VERSION_LESS: return -1;
	case APK_VERSION_GREATER: return 1;
	default: return 0;
	}
}

int adb_r_pkgindex_find(struct adb_obj *arr, int cur, struct adb *db, adb_val_t val)
{
	adb_val_t *ndx;

	__db1 = db;
	__db2 = arr->db;

	if (cur == 0) {
		ndx = bsearch(&val, &arr->obj[ADBI_FIRST], adb_ra_num(arr), sizeof(arr->obj[0]), pkginfo_cmp);
		if (!ndx) return -1;
		cur = ndx - arr->obj;
		while (cur > 1 && pkginfo_cmp(&val, &arr->obj[cur-1]) == 0) cur--;
	} else {
		cur++;
		if (pkginfo_cmp(&val, &arr->obj[cur]) != 0)
			return -1;
	}
	return cur;

}

unsigned int adb_pkg_field_index(char f)
{
#define MAP(ch, ndx) [ch - 'A'] = ndx
	static unsigned char map[] = {
		MAP('C', ADBI_PI_UNIQUE_ID),
		MAP('P', ADBI_PI_NAME),
		MAP('V', ADBI_PI_VERSION),
		MAP('T', ADBI_PI_DESCRIPTION),
		MAP('U', ADBI_PI_URL),
		MAP('I', ADBI_PI_INSTALLED_SIZE),
		MAP('S', ADBI_PI_FILE_SIZE),
		MAP('L', ADBI_PI_LICENSE),
		MAP('A', ADBI_PI_ARCH),
		MAP('D', ADBI_PI_DEPENDS),
		MAP('i', ADBI_PI_INSTALL_IF),
		MAP('p', ADBI_PI_PROVIDES),
		MAP('o', ADBI_PI_ORIGIN),
		MAP('m', ADBI_PI_MAINTAINER),
		MAP('t', ADBI_PI_BUILD_TIME),
		MAP('c', ADBI_PI_REPO_COMMIT),
		MAP('r', ADBI_PI_REPLACES),
		MAP('k', ADBI_PI_PRIORITY),
	};
	if (f < 'A' || f-'A' >= ARRAY_SIZE(map)) return 0;
	return map[(unsigned char)f - 'A'];
}
