## How to run

python3 driver.py <full_path_to_aeres_binary> <full_path_to_root_store> <path_to_certificate_chain>

### Example (for Linux)

python3 driver.py /home/aeres-external-driver/aeres /etc/ssl/certs/ca-certificates.crt certs/www-google-com-chain.pem

### Example (for Mac)

python3 driver.py /home/aeres-external-driver/aeres_mac /etc/ssl/certs/ca-certificates.crt certs/www-google-com-chain.pem


### TODO

install morpheus oracle

install hacl-star [gcc -o hash-hacl-star-bin hash-hacl-star.c -I /home/joyanta/Desktop/hacl-star/dist/gcc-compatible/ -I /home/joyanta/Desktop/hacl-star/dist/karamel/include -I /home/joyanta/Desktop/hacl-star/dist/karamel/krmllib/dist/minimal /home/joyanta/Desktop/hacl-star/dist/gcc-compatible/libevercrypt.a]

install whymp [gcc mex-whymp.c -I /home/joyanta/Desktop/whymp/lib /home/joyanta/Desktop/whymp/libwmp.a -o mex-whymp]
