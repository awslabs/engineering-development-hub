/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Minimal MPI ping-pong latency probe for the EDH Apptainer EFA sample.
 *
 * Deliberately tiny and dependency-free: it must compile with the container's
 * own mpicc so the measurement exercises the container's MPI and libfabric,
 * which is exactly the ABI pairing under test. Pulling in OSU or Intel MPI
 * Benchmarks would measure more but would also add a download and a build the
 * sample cannot rely on having network access for.
 *
 * Reports the HALF round-trip, which is the conventional one-way latency figure
 * and is what the EFA and TCP numbers are compared on.
 */

#include <mpi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define WARMUP_ITERS 200
#define TIMED_ITERS 1000
#define PAYLOAD_BYTES 8

int main(int argc, char **argv)
{
    int rank = 0;
    int size = 0;
    int i;
    char host[256];
    char buf[PAYLOAD_BYTES];
    double t0, t1, elapsed_us, half_rtt_us;

    MPI_Init(&argc, &argv);
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);

    if (size != 2) {
        if (rank == 0) {
            fprintf(stderr,
                    "this probe needs exactly 2 ranks, got %d\n", size);
        }
        MPI_Abort(MPI_COMM_WORLD, 1);
        return 1;
    }

    memset(buf, 'x', sizeof(buf));
    if (gethostname(host, sizeof(host)) != 0) {
        strncpy(host, "unknown", sizeof(host) - 1);
        host[sizeof(host) - 1] = '\0';
    }

    /* Report placement, so a run that accidentally put both ranks on one node
     * is obvious in the job output rather than silently reporting shared-memory
     * latency as though it were fabric latency. */
    printf("rank %d of %d on %s\n", rank, size, host);
    fflush(stdout);
    MPI_Barrier(MPI_COMM_WORLD);

    for (i = 0; i < WARMUP_ITERS; i++) {
        if (rank == 0) {
            MPI_Send(buf, PAYLOAD_BYTES, MPI_CHAR, 1, 0, MPI_COMM_WORLD);
            MPI_Recv(buf, PAYLOAD_BYTES, MPI_CHAR, 1, 0, MPI_COMM_WORLD,
                     MPI_STATUS_IGNORE);
        } else {
            MPI_Recv(buf, PAYLOAD_BYTES, MPI_CHAR, 0, 0, MPI_COMM_WORLD,
                     MPI_STATUS_IGNORE);
            MPI_Send(buf, PAYLOAD_BYTES, MPI_CHAR, 0, 0, MPI_COMM_WORLD);
        }
    }

    MPI_Barrier(MPI_COMM_WORLD);
    t0 = MPI_Wtime();

    for (i = 0; i < TIMED_ITERS; i++) {
        if (rank == 0) {
            MPI_Send(buf, PAYLOAD_BYTES, MPI_CHAR, 1, 0, MPI_COMM_WORLD);
            MPI_Recv(buf, PAYLOAD_BYTES, MPI_CHAR, 1, 0, MPI_COMM_WORLD,
                     MPI_STATUS_IGNORE);
        } else {
            MPI_Recv(buf, PAYLOAD_BYTES, MPI_CHAR, 0, 0, MPI_COMM_WORLD,
                     MPI_STATUS_IGNORE);
            MPI_Send(buf, PAYLOAD_BYTES, MPI_CHAR, 0, 0, MPI_COMM_WORLD);
        }
    }

    t1 = MPI_Wtime();

    if (rank == 0) {
        elapsed_us = (t1 - t0) * 1000000.0;
        half_rtt_us = elapsed_us / (double) TIMED_ITERS / 2.0;
        printf("iterations: %d, payload: %d bytes\n",
               TIMED_ITERS, PAYLOAD_BYTES);
        printf("half-round-trip latency: %.2f us\n", half_rtt_us);
        fflush(stdout);
    }

    MPI_Finalize();
    return 0;
}
