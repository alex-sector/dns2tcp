#include <stdio.h>
#include <string.h>

int             optind = 1;
int             optopt;
char           *optarg;

/**
 * @brief get command line arguments
 * @param[in] argc
 * @param[in] argv 
 * @param[in] opts options available
 **/

int getopt(int argc, char **argv, char *opts)
{
  static int      sp = 1;
  register int    c;
  register char  *cp;

  if (sp == 1)
    if (optind >= argc ||
	argv[optind][0] != '-' || argv[optind][1] == '\0')
      return -1;
    else if (strcmp(argv[optind], "--") == 0)
    {
      optind++;
      return -1;
    }
  optopt = c = argv[optind][sp];
  if (c == ':' || !(cp = strchr(opts, c)))
  {
    fprintf(stderr, "%c: illegal option -- \n", c);
    if (argv[optind][++sp] == '\0')
    {
      optind++;
      sp = 1;
    }
    return ('?');
  }
  if (*++cp == ':')
  {
    if (argv[optind][sp + 1] != '\0')
      optarg = &argv[optind++][sp + 1];
    else if (++optind >= argc)
    {
      fprintf(stderr, "%c: option requires an argument -- \n", c);
      sp = 1;
      return ('?');
    } else
      optarg = argv[optind++];
    sp = 1;
  } else
  {
    if (argv[optind][++sp] == '\0')
    {
      sp = 1;
      optind++;
    }
    optarg = NULL;
  }
  return (c);
}

