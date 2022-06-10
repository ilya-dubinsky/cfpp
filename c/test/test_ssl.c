#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "test_io.h"

#define HOST_NAME "baltimore-cybertrust-root.chain-demos.digicert.com"
#define HOST_PORT "443"
#define HOST_RESOURCE "/"
//#define HOST_RESOURCE "/cgi-bin/randbyte?nbytes=32&format=h"

void test_ssl_connection() {
	SSL_CTX * context = NULL;
	BIO * ssl_connection =  NULL;
	BIO * out = NULL;
	SSL *ssl = NULL;

	char error_message_buffer[4096];

	long error_code;
	print_test_header("SSL connectivity test");

	print_test_step(1, "Initialize and configure the TLS client");
	/* Initialize the SSL context. We are the client */
	context = SSL_CTX_new(TLS_client_method());

	/* Ensure the version of the protocol is at least TLS 1.2 to avoid downgrades to a vulnerable
	 * TLS version */
	if (1!=SSL_CTX_set_min_proto_version(context, TLS1_2_VERSION))
		goto cleanup;

	/* configure allowed ciphersuites */
	if (1!=SSL_CTX_set_ciphersuites(context, "TLS_AES_128_GCM_SHA256:TLS_AES_128_CCM_SHA256"))
		goto cleanup;

	print_test_step(2, "Load the certificate file");
	/* verify peer certificates */
	if (1!=SSL_CTX_load_verify_locations(context, "data/cert.pem", NULL))
		goto cleanup;

	SSL_CTX_set_verify(context, SSL_VERIFY_PEER, NULL);
	SSL_CTX_set_verify_depth(context, 1);

	print_test_step(2, "Connect to the server");
	/* instantiate new connection using BIO*/
	ssl_connection = BIO_new_ssl_connect(context);
	printf ("\tConnection instantiated\n");
	BIO_set_conn_hostname(ssl_connection, HOST_NAME ":" HOST_PORT);

	BIO_get_ssl(ssl_connection, &ssl);

	/* set the host name extension value */
	SSL_set_tlsext_host_name(ssl, HOST_NAME);
	printf ("\tHost name set\n");

	/* connect to the server */
	if (1!=BIO_do_connect(ssl_connection))
		goto cleanup;
	printf ("\tServer connection opened\n");

	print_test_step(3, "Perform handshake");
	/* do handshake */
	if (1!=BIO_do_handshake(ssl_connection))
		goto cleanup;

	printf("\tHandshake successful, dumping the certificate");
	/* dump the certificate */
	X509* cert = SSL_get_peer_certificate(ssl);
	if (cert){
		X509_print_fp(stdout, cert);
		X509_free(cert);
	}

	out = BIO_new_fp(stdout, BIO_NOCLOSE);

	print_test_step(4, "Send an HTTP request");
	BIO_puts(ssl_connection, "GET " HOST_RESOURCE " HTTP/1.1\r\n"
	              "Host: " HOST_NAME "\r\n"
	              "Connection: close\r\n\r\n");
	BIO_puts(out, "\n");
	printf("\tRequest sent\n");

	print_test_step(5, "Read and dump the response");
	int len = 0;
	do
	{
	  char buff[1536];
	  len = BIO_read(ssl_connection, buff, sizeof(buff));

	  if(len > 0)
	    BIO_write(out, buff, len);

	} while (len > 0 || BIO_should_retry(ssl_connection));

	printf("Response done\n");
	print_test_footer("SSL connectivity test");
cleanup:

	error_code = ERR_get_error();
	if (error_code) {
		ERR_error_string(error_code, error_message_buffer);
		printf("ERROR: %s\n", error_message_buffer);
	}

	if (!context)
		SSL_CTX_free(context);
	if (!ssl_connection)
		BIO_free(ssl_connection);
	if (!out)
		BIO_free(out);
}

int main (void) {
	test_ssl_connection();
}
