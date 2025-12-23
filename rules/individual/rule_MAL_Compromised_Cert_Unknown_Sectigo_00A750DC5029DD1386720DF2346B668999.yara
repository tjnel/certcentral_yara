import "pe"

rule MAL_Compromised_Cert_Unknown_Sectigo_00A750DC5029DD1386720DF2346B668999 {
   meta:
      description         = "Detects Unknown with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-15"
      version             = "1.0"

      hash                = "4183ce92541a0f8408573a2eaba2beec8decf624b30d101d5e551372b3cba425"
      malware             = "Unknown"
      malware_type        = "Initial access tool"
      malware_notes       = "The malware was observed being distributed through advertising for a Bit Warden installer: https://jeromesegura.com/malvertising/2025/11/11-22-2025_Bitwardenmac . The malware contains a password protected Zip which is unzipped and the contents are executed: https://app.any.run/tasks/ad50c34d-ee30-42e2-be20-0f4c5f4dfbdf/"

      signer              = "LIFT AID SERVICES LIMITED"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV E36"
      cert_serial         = "00:a7:50:dc:50:29:dd:13:86:72:0d:f2:34:6b:66:89:99"
      cert_thumbprint     = "8A78EB44BECA59781CB91C0931AAB1087C4AC18B"
      cert_valid_from     = "2025-10-15"
      cert_valid_to       = "2026-10-15"

      country             = "GB"
      state               = "London, City of"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "14302945"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV E36" and
         sig.serial == "00:a7:50:dc:50:29:dd:13:86:72:0d:f2:34:6b:66:89:99"
      )
}
