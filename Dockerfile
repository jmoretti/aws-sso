FROM python:3-alpine

# Set environment variables.
ENV HOME /root

# Define working directory.
WORKDIR /root

# Add scripts and config data and install dependancies
COPY . /root
RUN chmod +x /root/aws-sso.py &&\ 
    pip install --no-cache-dir -r requirements.txt

CMD [ "python3", "./aws-sso.py" ]