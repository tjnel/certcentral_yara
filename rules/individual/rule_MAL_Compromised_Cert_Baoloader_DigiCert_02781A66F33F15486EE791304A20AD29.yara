import "pe"

rule MAL_Compromised_Cert_Baoloader_DigiCert_02781A66F33F15486EE791304A20AD29 {
   meta:
      description         = "Detects Baoloader with compromised cert (DigiCert)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2018-08-02"
      version             = "1.0"

      hash                = "6b6fc62a294d5ef1c619d623f1cf6d735d9f191df9ef5c745b0881b1e01b8565"
      malware             = "Baoloader"
      malware_type        = "Backdoor"
      malware_notes       = "This malware was originally used for adfraud but is a risk due to an arbitrary backdoor. For more information see https://expel.com/blog/the-history-of-appsuite-the-certs-of-the-baoloader-developer/ and https://www.gdatasoftware.com/blog/2025/08/38257-appsuite-pdf-editor-backdoor-analysis"

      signer              = "Realistic Media Inc."
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert EV Code Signing CA (SHA2)"
      cert_serial         = "02:78:1a:66:f3:3f:15:48:6e:e7:91:30:4a:20:ad:29"
      cert_thumbprint     = "19562FFE771A7BBF5A144F70812DFDFFE1FA04EC"
      cert_valid_from     = "2018-08-02"
      cert_valid_to       = "2019-08-06"

      country             = "VG"
      state               = "???"
      locality            = "Road Town"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert EV Code Signing CA (SHA2)" and
         sig.serial == "02:78:1a:66:f3:3f:15:48:6e:e7:91:30:4a:20:ad:29"
      )
}
