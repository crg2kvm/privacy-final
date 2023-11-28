from flask import Flask, request, render_template
from PIL import Image
import hashlib
import io
import sqlite3

app = Flask(__name__)

def imageToString(image):
    im = Image.open(image,'r')
    pixels = list(im.getdata())
    stringIMG = ""
    for i in pixels:
        for value in i:
            stringIMG += str(value)
    return stringIMG

def stringToHash(imgString):
    hash_function = hashlib.sha256()
    hash_function.update(imgString.encode())
    return hash_function.hexdigest()

def save_hash_to_db(image_hash):
    conn = sqlite3.connect('imagehashes.db')
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS hashes (hash TEXT)')
    c.execute('INSERT INTO hashes VALUES (?)', (image_hash,))
    conn.commit()
    conn.close()


@app.route('/')
def index():
    return render_template('index.html')

def clear_database():
    conn = sqlite3.connect('imagehashes.db')
    c = conn.cursor()
    c.execute('DELETE FROM hashes')
    conn.commit()
    conn.close()

@app.route('/clear_db')
def clear_db():
    clear_database()
    return 'Database cleared'

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            return 'No file part'
        file = request.files['file']
        if file.filename == '':
            return 'No selected file'
        if file:
            imgString = imageToString(io.BytesIO(file.read()))
            image_hash = stringToHash(imgString)
            if hash_exists_in_db(image_hash):
                return 'Hash is already in database'
            else:
                save_hash_to_db(image_hash)
                return 'Image hash: ' + image_hash
    return render_template('upload.html')


def hash_exists_in_db(image_hash):
    conn = sqlite3.connect('imagehashes.db')
    c = conn.cursor()
    c.execute('SELECT EXISTS(SELECT 1 FROM hashes WHERE hash=? LIMIT 1)', (image_hash,))
    exists = c.fetchone()[0]
    conn.close()
    return exists

@app.route('/search', methods=['GET', 'POST'])
def search_hash():
    if request.method == 'POST':
        file = request.files['file']
        if file:
            imgString = imageToString(io.BytesIO(file.read()))
            image_hash = stringToHash(imgString)
            exists = hash_exists_in_db(image_hash)
            message = 'Hash exists in database' if exists else 'Hash does not exist in database'
            return message
    return render_template('search.html')

@app.route('/compare', methods=['GET','POST'])
def compare_images():
    if request.method == 'POST':
        file1 = request.files['file1']
        file2 = request.files['file2']

        if file1 and file2:
            imgString1 = imageToString(io.BytesIO(file1.read()))
            imgString2 = imageToString(io.BytesIO(file2.read()))

            hash1 = stringToHash(imgString1)
            hash2 = stringToHash(imgString2)

            if hash1 == hash2:
                return "The images have the same hash."
            else:
                return "The images have different hashes."
    return render_template('compare.html')


if __name__ == '__main__':
    app.run(debug=True)
