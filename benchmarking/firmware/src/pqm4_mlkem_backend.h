#pragma once

/*
 * Register the pqm4 ML-KEM callback backend with wolfSSL.
 */
int pqm4_mlkem_backend_init(void);
/*
 * Return the wolfSSL device identifier assigned to pqm4 ML-KEM.
 */
int pqm4_mlkem_backend_dev_id(void);
