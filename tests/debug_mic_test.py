import traceback
import tests.test_microphone_location_consent as t

print('Running get_location test')
try:
    t.test_get_location_requires_consent_and_fetches()
    print('get_location passed')
except Exception:
    traceback.print_exc()

print('\nRunning mic consent test')
try:
    t.test_microphone_consent_enables_listening()
    print('microphone consent passed')
except Exception:
    traceback.print_exc()
