package tenantname

import "testing"

func TestReservedMasterRejectsProtectedUnicodeSpoofs(t *testing.T) {
	for _, value := range []string{
		"Code Foundry",
		"C0de Foundry",
		"Cod3 Foundry",
		"C0d3 F0undry",
		"Cod℮ Foundry",
		"Code Foundr¥",
		"Code F0undry",
		"Ｃｏｄｅ　Ｆｏｕｎｄｒｙ",
		"Códé-Foundry",
		"Code Foundρy",
		"Сοԁе Ғοսոԁгу",
		"ꓚꓳꓓꓰ ꓝꓳꓴꓠꓓꓣꓬ",
		"ᴄᴏᴅᴇ ꜰᴏᴜɴᴅʀʏ",
		"Code Foundry · MASTER",
		"MASTER / Code Foundry",
	} {
		if !ReservedMaster(value) {
			t.Errorf("protected MASTER spoof was accepted: %q", value)
		}
	}
}

func TestReservedMasterDoesNotBlockUnrelatedInternationalNames(t *testing.T) {
	for _, value := range []string{"Bereia", "Fundação Esperança", "Ελληνική Κοινότητα", "東京 Foundry"} {
		if ReservedMaster(value) {
			t.Errorf("unrelated tenant name was reserved: %q", value)
		}
	}
}
