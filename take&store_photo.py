import cv2
import os

folder_name = "my_photos"

if not os.path.exists(folder_name):
    os.makedirs(folder_name)

videoCaptureObject = cv2.VideoCapture(0)
result = True
while result:
    ret, frame = videoCaptureObject.read()
    photo_path = os.path.join(folder_name, "NewPicture.jpg")
    cv2.imwrite(photo_path, frame)
    result = False

videoCaptureObject.release()
cv2.destroyAllWindows()

print(f"Photo saved in the '{folder_name}' folder as 'NewPicture.jpg'")