import os
import logging
from unittest import TestCase
from enocean.protocol.eep import EEP


class TestEEPCoverage(TestCase):
    def setUp(self):
        self.eep = EEP()

    def test_io_error(self):
        ''' Test IOError handling '''
        eep_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'EEP.xml')
        backup_path = eep_path + '.bak'
        # ensure backup does not exist
        if os.path.exists(backup_path):
            os.remove(backup_path)
        os.rename(eep_path, backup_path)
        with self.assertLogs('enocean.protocol.eep', level='WARNING') as cm:
            eep = EEP()
            self.assertFalse(eep.init_ok)
            self.assertEqual(cm.output, ['WARNING:enocean.protocol.eep:Cannot load protocol file!'])
        os.rename(backup_path, eep_path)

    def test_find_profile_invalid_rorg(self):
        ''' Test find_profile with invalid RORG '''
        with self.assertLogs('enocean.protocol.eep', level='WARNING') as cm:
            self.assertIsNone(self.eep.find_profile([], 0xFF, 0xFF, 0xFF))
            self.assertEqual(cm.output, ["WARNING:enocean.protocol.eep:Cannot find rorg 0xff in EEP!"])

    def test_set_values_invalid_shortcut(self):
        ''' Test set_values with invalid shortcut '''
        profile = self.eep.find_profile([], 0xF6, 0x02, 0x02)
        with self.assertLogs('enocean.protocol.eep', level='WARNING') as cm:
            data, status = self.eep.set_values(profile, [0] * 8, 0, {'invalid_shortcut': 0})
            self.assertEqual(data, [0] * 8)
            self.assertEqual(status, 0)
            self.assertEqual(cm.output, ["WARNING:enocean.protocol.eep:Cannot find data description for shortcut invalid_shortcut"])
