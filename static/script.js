document.addEventListener("DOMContentLoaded", function () {

    // Handle "Download CA Certificate" buttons
    document.querySelectorAll(".download-ca-cert-btn").forEach(button => {
        button.addEventListener("click", function (event) {
            event.preventDefault();
            const certName = this.getAttribute("cert-name");
            console.log(`Downloading certificate: ${certName}`);
            window.location.href = `/download_ca_certificate/${certName}`;
        });
    });

    // Handle "View CA Certificate" buttons
    document.querySelectorAll(".view-ca-cert-btn").forEach(button => {
        button.addEventListener("click", function (event) {
            event.preventDefault();
            console.log("view ca cert button clicked");
            const certName = this.getAttribute("cert-name");
            console.log(`Viewing certificate: ${certName}`);
            window.location.href = `/certificate_details/${certName}/ca_certificate`;
        });
    });

    // Handle "Download CA CRL" buttons
    document.querySelectorAll(".download-crl-btn").forEach(button => {
        button.addEventListener("click", function (event) {
            event.preventDefault();
            const crlName = this.getAttribute("crl-name");
            console.log(`Downloading CRL: ${crlName}`);
            window.location.href = `/download_crl/${crlName}`;
        });
    });

    // Handle "View CA CRL" buttons
    document.querySelectorAll(".view-crl-btn").forEach(button => {
        button.addEventListener("click", function () {
            const crlName = this.getAttribute("crl-name");
            console.log(`Viewing CRL: ${crlName}`);
            window.location.href = `/crl_details/${crlName}/ca_crl`;
        });
    });
});
