import "pe"

rule MAL_Compromised_Cert_BaoLoader_SSL_com_1709C0F1042395431C1283C6412C4BA5 {
   meta:
      description         = "Detects BaoLoader with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-07-02"
      version             = "1.0"

      hash                = "7022b6b2caa7ecfc1a9575b74cce793336fc5fe4571955b1240716d9ab4b9e84"
      malware             = "BaoLoader"
      malware_type        = "Backdoor"
      malware_notes       = "This malware was originally used for adfraud but is a risk due to an arbitrary backdoor. For more information see https://expel.com/blog/the-history-of-appsuite-the-certs-of-the-baoloader-developer/ and https://www.gdatasoftware.com/blog/2025/08/38257-appsuite-pdf-editor-backdoor-analysis"

      signer              = "Eclipse Media Inc"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "17:09:c0:f1:04:23:95:43:1c:12:83:c6:41:2c:4b:a5"
      cert_thumbprint     = "53E58D93DC1DDC3493C0054DA2FE04F381B5F08D"
      cert_valid_from     = "2024-07-02"
      cert_valid_to       = "2027-07-02"

      country             = "PA"
      state               = "???"
      locality            = "Panama City"
      email               = "???"
      rdn_serial_number   = "155704432"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "17:09:c0:f1:04:23:95:43:1c:12:83:c6:41:2c:4b:a5"
      )
}
