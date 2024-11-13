from flask import Flask, render_template, request, redirect, url_for, session, flash

app = Flask(__name__)
app.secret_key = ''

# Team Member 1: Craig: User Authentication
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    # registration logic
    if request.method == 'POST':
        # Collect form data and perform registration
        flash('Registration feature coming soon.')
        return redirect(url_for('register'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # login logic
    if request.method == 'POST':
        # Collect form data and perform authentication
        flash('Login feature coming soon.')
        return redirect(url_for('login'))
    return render_template('login.html')

# Team Member 2: Message Handling
@app.route('/inbox')
def inbox():
    # inbox display
    flash('Inbox feature coming soon.')
    return render_template('inbox.html')

@app.route('/send', methods=['GET', 'POST'])
def send_message():
    #  sending messages
    if request.method == 'POST':
        flash('Message sending feature coming soon.')
        return redirect(url_for('send_message'))
    return render_template('send.html')

if __name__ == '__main__':
    app.run(debug=True)
