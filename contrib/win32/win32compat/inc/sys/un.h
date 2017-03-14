#pragma once

struct	sockaddr_un {
	short	sun_family;		/* AF_UNIX */
	char	sun_path[108];		/* path name (gag) */
};

