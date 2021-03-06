#ifndef _DIRUTIL_H_
#define _DIRUTIL_H_

/**
 * dirutil_fsyncdir(path):
 * Call fsync on the directory ${path}.
 */
int dirutil_fsyncdir(const char *);

/**
 * build_dir(dir, diropt):
 * Makes sure that ${dir} exists, creating it (and any parents) as necessary.
 */
int build_dir(const char *, const char *);

#endif /* !_DIRUTIL_H_ */
