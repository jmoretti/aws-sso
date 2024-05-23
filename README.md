# aws-sso

This utility will log you into the AWS SSO portal, list all AWS accounts and roles you have access to and create profiles for each of them in your AWS configuration file and temporary credentials in your AWS credential file for non-SSO capable AWS utilities.

The script requires python3 and dependencies can be installed with pip:
```
pip install -r requirements.txt
```

It can be run via [Docker](https://docs.docker.com/get-docker/):
```
docker run -it --rm -v ~/.aws:/root/.aws aws-sso
```

An alias can be added to your shell profile, for example on Bash:
```
alias aws-sso='docker run -it --rm -v ~/.aws:/root/.aws aws-sso'
```

If needed, you can build the Docker image:
```
docker build . -t aws-sso
```

One logged in you can use the [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) with the --profile option to access any account and role you have access to, for example to show my user information in an account called demo with a role called read, I could run the following command :
```
aws sts get-caller-identity --profile demo-read
```
The contant "AWS_DEFAULT_SSO_START_URL" must be set to the AWS access portal URL configured in IAM Identity Center. 

The utility will use an optional tag called "cliName" on the account (configurable in AWS Organizations) and will use that instead of the actual AWS account name if available.  The utility will use shortened roles names defined in the script as ROLECLINAMES if available.

To use this capability, you need to create the following policy in IAM Idenity Center and assign it to your root account with the role name "SSO-default".  You will need to update the script and set the constant "AWS_DEFAULT_SSO_ACCOUNT_ID" equal to the AWS account ID of that root account.

```
{
	"Version": "2012-10-17",
	"Statement": [
		{
			"Sid": "Statement1",
			"Effect": "Allow",
			"Action": [
				"organizations:ListTagsForResource"
			],
			"Resource": [
				"*"
			]
		}
	]
}
```

