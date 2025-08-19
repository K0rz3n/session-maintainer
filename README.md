# Session-Maintainer


![usage_display](./images/usage_display.png)


**Session-Maintainer** is a highly configurable automation tool that supports automatic acquisition of website sessions through Chrome and API requests, persistence based on MySQL, and can be automatically maintained and updated. It can serve as a cornerstone for security scanning and automated verification.

The project's prototype is the login state maintenance module of a scanner, whose **operation mode has been refined and validated through long-term practical use**. It has now been reorganized and restructured for open-source sharing.

**The advantages of this project are:**

- **Multiple modes**: Support WEB browser simulation and interface request two modes to obtain website cookies/tokens
- **Multiple sources**: Supports extracting specified keys and values from urls, headers, cookies, body and other locations of data packets
- **Persistible**: Supports persistence of sessions using database
- **Automatic update**: Supports configuring multiple update mechanisms such as single time, timing and period, and automatically check the validity of persistent login states and update it
- **Highly customized**: Supports extracting different session tokens (SSO scenarios) that appear in the same application, and also supports any non-token but need to be passed during requests using kv values
- **Machine verification Bypass**: Supports human front-end simulation login, bypassing dynamic anti-human-machine nuclear mechanisms such as sliding verification codes
- **Asynchronous task**: Supports the number of processes to configure the message queue to achieve multi-process parallelism, and uses two queues: simulate and http, and parallel execution significantly improves efficiency



## Installation

```
This project has only been tested in Mac M1 environments. There may be problems with Windows and Linux, python >= 3.12
``` 

### System dependencies installation 

This project needs to depend on system-level software such as [chrome](https://www.google.com/chrome/), [mysql](https://www.mysql.com/), [playwright](https://playwright.dev/), [rabbitmq](https://www.rabbitmq.com/), etc. Please search for the installation method yourself.

```
1. rabbitmq: Message queue, used to accept tasks, currently only supports installation locally, and uses default password
2. mysql: database, used for session persistence, you can configure your account password in ./configs/config.py
3. playwright: An automated framework, used to invoke Chrome for login action recording
4. Chrome: Browser, used to perform simulated login in simulated mode, and obtain session
```

### Project dependencies installation

```
# Create a python virtual environment
python3 -m venv .venv

# Activate the ython virtual environment
source .venv/bin/activate

# Install project dependencies
pip install -r requirements.txt

# Install the browser that playwright is adapted to
python3 -m playwright install chromium
```


## Running

### Start the system service

```
# Start rabbitmq message middleware
rabbitmq-server

# Start MySQL service
brew services start mysql
```

### Configuration file editing

```
Please read the comments in configs/config.py to understand global configuration

Please read the example files in modules/simulate and modules/http to understand the configuration of the application
```

If you need to use simulate mode, please use the following command to record the login action, process the generated python code and put it into the login function in the template.

```
python -m playwright codegen --target python https://example.com/login
```

### Project start

```
python3 maintainer.py
```

### monitor

```
# Check the queue status
rabbitmqctl listqueues -p / name

# View messages for delayed queues
rabbitmqctl listqueues -p / name messages consumers

# Clean up the queue
rabbitmqadmin purge queue name=simulate

rabbitmqadmin purge queue name=http
```


## Todo List

- Support the recalculation of signature before the API interface verification request is initiated.

- Support verification code recognition and automatic filling

- Support the location and name of custom queues

- Supports Windows and Linux environments

- Detailed function introduction and usage documentation 
