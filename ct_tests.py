# test_ct_guard.py
import unittest
import os
import subprocess

from ct_guard import ct_check_binary, EXIT_CT, EXIT_NOT_CT

def make_test_function(binary_path, expected_failure):
    def test(self):
        print('testing',binary_path)
        try:
            ct_check_binary(binary_path)
        except SystemExit as e:
            if expected_failure:
                self.assertEqual(e.code, EXIT_NOT_CT, "%s was expected to fail but exited with %d." % (binary_path, e.code))
            else:
                self.assertEqual(e.code, EXIT_CT, "%s was expected to succeed but exited with %d." % (binary_path, e.code))
        else:
            if expected_failure:
                self.fail("%s was expected to fail but did not exit." % binary_path)
    return test


class TestConstantTimeOperations(unittest.TestCase):
    pass

def generate_test_cases():
    directory = '/ct-checker-2/ct_tests'
    # Loop through all files in the directory
    for filename in os.listdir(directory):
        # Construct the full path
        filepath = os.path.join(directory, filename)
        # Check if it's a file and a binary executable
        # if os.path.isfile(filepath) and not filename.endswith('.c') and not filename.endswith('.h') and 'Makefile' not in filename and not filename.endswith('.notest'):
        if os.path.isfile(filepath) and not os.path.splitext(filename)[1] and filename != 'Makefile':
            expected_failure = 'high' in filename
            test_func = make_test_function(filepath, expected_failure)
            test_name = 'test_{}'.format(filename.replace('.', '_'))
            setattr(TestConstantTimeOperations, test_name, test_func)

generate_test_cases()

if __name__ == '__main__':
    unittest.main()
