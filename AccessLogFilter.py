import os,hashlib,time
from flask import Flask, render_template, request, redirect, url_for,send_from_directory
from run import RunLine

UPLOAD_FOLDER = r'C:\Users\yuxuliu\PycharmProjects\AccessLogFilter\tmp'
ALLOWED_EXTENSIONS = ['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif']

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/',methods=['GET','POST'])
def upload_file():
    if request.method== 'POST':
        file = request.files['file']
        if file:
            filehash=hashlib.sha1(file.filename.encode()).hexdigest()
            filetime=time.strftime('%Y%m%d_%H%M%S',time.localtime(time.time()))
            fileformat=file.filename.split('.')[-1]
            filename=file.filename.split('.')[0]+'_'+filehash+'_'+filetime+'.'+fileformat
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            # print(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            return redirect(url_for('result',filename=filename))
    return render_template(["index.html"])

@app.route('/analysis',methods=['POST','GET'])
def analysis():
    try:
        Textarea = request.form.get('textcontent', type=str, default=None).split('\r\n')
        return render_template(["index.html"],
                           errors='Analysis done.',
                           items=RunLine(Textarea)
                           )
    except AttributeError:
        return render_template(["index.html"],
                               errors='Please input accesslogs line by line.')
    except NameError:
        return render_template(["index.html"],
                               errors='Please input accesslogs line by line.')
    except IndexError:
        # return redirect('/')
        return render_template(["index.html"],
                               errors='Log Format Error. Please input accesslogs line by line.')
    except TypeError:
        # return redirect('/')
        return render_template(["index.html"],
                               errors='Log Format Error. Please input accesslogs line by line.')
@app.route('/uploads/<filename>')
def result(filename):
    try:
        f=open(os.path.join(app.config['UPLOAD_FOLDER'], filename),'r')
        return render_template(["index.html"],
                               items=RunLine(f.readlines())
                               )
    except FileNotFoundError:
        return redirect('/')
    # return send_from_directory(app.config['UPLOAD_FOLDER'],filename)

if __name__ == '__main__':
    app.run()