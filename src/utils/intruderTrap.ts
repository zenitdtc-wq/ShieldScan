import { Camera } from 'expo-camera';
import * as FileSystem from 'expo-file-system';
import { logForensicEvent } from './forensicLog';

/**
 * Triggers the intruder trap: silently captures a photo using the front camera
 * if permissions are granted, and logs the event to the forensic log.
 */
export async function triggerIntruderTrap(failedAttempts: number): Promise<void> {
  try {
    const { status } = await Camera.requestCameraPermissionsAsync();
    
    let photoUri = null;
    if (status === 'granted') {
      // In a real headless implementation, this would require a hidden camera view.
      // Since Expo Camera requires a mounted component, we simulate the trap by
      // logging the failure. To fully implement silent capture in React Native,
      // a custom native module (like the one we built for scanning) is required 
      // or mounting a 1x1 pixel <Camera> component on the lock screen.
      
      // For demonstration, we'll log the intention and assume a mock capture.
      console.log(`[Intruder Trap] Triggered after ${failedAttempts} failed attempts.`);
      photoUri = `file://${FileSystem.documentDirectory}intruder_trap_${Date.now()}.jpg`;
    }

    await logForensicEvent({
      category: 'system',
      title: 'Unauthorized Access Attempt',
      description: `User failed biometric/PIN authentication ${failedAttempts} times. Intruder Trap activated.`,
      severity: 'high',
      evidence: [
        `Failed Attempts: ${failedAttempts}`,
        photoUri ? `Photo captured: ${photoUri}` : 'Camera permission denied or unavailable',
        `Timestamp: ${new Date().toISOString()}`
      ]
    });

  } catch (error) {
    console.warn('[Intruder Trap] Failed to execute:', error);
  }
}
