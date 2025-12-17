import "pe"

rule MAL_Compromised_Cert_BaoLoader_SSL_com_5D9B7E3724B3222A7E0265E0636D62F0 {
   meta:
      description         = "Detects BaoLoader with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-04-03"
      version             = "1.0"

      hash                = "f7fb16a3b5ca5a4970b8fc1866849162707a5a65a15d1498728ce27277c9ad52"
      malware             = "BaoLoader"
      malware_type        = "Backdoor"
      malware_notes       = "This malware was originally used for adfraud but is a risk due to an arbitrary backdoor. For more information see https://expel.com/blog/the-history-of-appsuite-the-certs-of-the-baoloader-developer/ and https://www.gdatasoftware.com/blog/2025/08/38257-appsuite-pdf-editor-backdoor-analysis"

      signer              = "Digital Promotions Sdn. Bhd."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "5d:9b:7e:37:24:b3:22:2a:7e:02:65:e0:63:6d:62:f0"
      cert_thumbprint     = "078D1597664ED2771756C53E3FCD13A3A4B12D81"
      cert_valid_from     = "2024-04-03"
      cert_valid_to       = "2027-04-02"

      country             = "MY"
      state               = "Johor"
      locality            = "Skudai"
      email               = "???"
      rdn_serial_number   = "202301011511"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "5d:9b:7e:37:24:b3:22:2a:7e:02:65:e0:63:6d:62:f0"
      )
}
