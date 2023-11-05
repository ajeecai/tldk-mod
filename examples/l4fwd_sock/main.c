/*
 * Copyright (c) 2016-2017  Intel Corporation.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <unistd.h>
#include "tle_sock.h"

int main(int argc, char *argv[])
{
	/////////// socket start //////////////
	int lcore = rte_lcore_id();
	int rc = 0;
	int listen_fd = -1, srv_fd = -1, clnt_fd = -1;
	const int sz = 1024;
	struct sockaddr_in serv_addr;
	char buf[sz];

	rc = sock_global_init(argc, argv);
	if (rc != 0)
	{
		exit(-1);
	}

	rc = sock_local_init();
	if (rc != 0)
	{
		exit(-1);
	}

	listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (listen_fd == -1)
	{
		printf("%s(%d), socket error: %d\n", __func__, lcore, errno);
		return -1;
	}

	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(5000);

	if (-1 == bind(listen_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)))
	{
		printf("%s(%d), bind error: %d\n", __func__, lcore, errno);

		return -1;
	}

	if (-1 == listen(listen_fd, 10))
	{
		printf("%s(%d), listen error: %d\n", __func__, lcore, errno);
		return -1;
	}

	while (1)
	{
		// sleep(1);

		tle_engine();

		if (srv_fd != -1)
		{
			rc = read(srv_fd, buf, sz - 1);
			if (rc > 0)
			{
				buf[rc - 1] = 0;
				printf("read returns (%d): %s\n", rc, rc > 0 ? buf : NULL);
				if (clnt_fd != -1)
				{
					write(clnt_fd, buf, rc);
				}
			}
			else if (rc == 0) // peer has closed the socket
			{
				printf("socket is closed, read returns (%d): %s, errno %d\n", rc, rc > 0 ? buf : NULL, errno);
				close(srv_fd);
				srv_fd = -1;

				close(clnt_fd);
				clnt_fd = -1;
			}
			else
			{
				if (rc == -1 && errno == EAGAIN) // normal case
				{
					// read again
				}
				else // exception
				{
					printf("error, read returns (%d): %s, errno %d\n", rc, rc > 0 ? buf : NULL, errno);
					close(srv_fd);
					srv_fd = -1;

					close(clnt_fd);
					clnt_fd = -1;
				}
			}

			continue;
		}

		srv_fd = accept(listen_fd, (struct sockaddr *)NULL, NULL);
		if (-1 == srv_fd)
		{
			// RTE_LOG(ERR, USER1, "%s(%d), accept error: %d\n", __func__, lcore, rte_errno);
			continue;
		}
		else
		{
			printf("srv_fd is %#x\n", srv_fd);

			struct sockaddr_in fwd_addr;
			memset(&fwd_addr, 0, sizeof(fwd_addr));
			fwd_addr.sin_family = AF_INET;
			fwd_addr.sin_addr.s_addr = htonl(0xc0a80abe); // 192.168.10.190, change it.
			fwd_addr.sin_port = htons(5001);
			clnt_fd = socket(AF_INET, SOCK_STREAM, 0);
			connect(clnt_fd, (const struct sockaddr *)&fwd_addr, sizeof(fwd_addr));
		}
	}

	return 0;
}
