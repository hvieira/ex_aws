defmodule ExAws.Irsa do
  @moduledoc false

  def credential_parser({:ok, %{body: xml} = resp}, :assume_role_with_web_identity) do
    import SweetXml

    parsed_body =
      xml
      |> SweetXml.xpath(~x"//AssumeRoleWithWebIdentityResponse",
        access_key_id: ~x"./AssumeRoleWithWebIdentityResult/Credentials/AccessKeyId/text()"s,
        secret_access_key:
          ~x"./AssumeRoleWithWebIdentityResult/Credentials/SecretAccessKey/text()"s,
        session_token: ~x"./AssumeRoleWithWebIdentityResult/Credentials/SessionToken/text()"s,
        expiration: ~x"./AssumeRoleWithWebIdentityResult/Credentials/Expiration/text()"s,
        assumed_role_id:
          ~x"./AssumeRoleWithWebIdentityResult/AssumedRoleUser/AssumedRoleId/text()"s,
        assumed_role_arn: ~x"./AssumeRoleWithWebIdentityResult/AssumedRoleUser/Arn/text()"s,
        request_id: ~x"./ResponseMetadata/RequestId/text()"s
      )

    {:ok, Map.put(resp, :body, parsed_body)}
  end

  def credentials(config) do
    token = retrieve_token(config)
    host_override = sts_endpoint(config)

    params = %{
      "Version" => "2011-06-15",
      "Action" => "AssumeRoleWithWebIdentity",
      "DurationSeconds" => "3600",
      "RoleSessionName" => Map.get(config, :session_name),
      "RoleArn" => Map.get(config, :role_arn),
      "WebIdentityToken" => token
    }

    response =
      %ExAws.Operation.Query{
        path: "/",
        params: params,
        service: :sts,
        action: :assume_role_with_web_identity,
        parser: &ExAws.Irsa.credential_parser/2
      }
      |> ExAws.Operation.perform(config |> Map.put(:host, host_override))

    case response do
      {:ok, result} ->
        %{
          access_key_id: result.body.access_key_id,
          secret_access_key: result.body.secret_access_key,
          security_token: result.body.session_token,
          expiration: result.body.expiration
        }

      error ->
        raise """
        AssumeRoleWithWebIdentity Error: #{inspect(error)}

        You tried to access to assume a role via a service account, but it could not be reached.
        This happens most often when trying to access it from your local computer,
        which happens when environment variables are not set correctly prompting
        ExAws to fallback to the Instance Meta.

        Please check your key config and make sure they're configured correctly:

        For Example:
        ```
        ExAws.Config.new(:s3)
        ExAws.Config.new(:dynamodb)
        ```
        """
    end
  end

  defp retrieve_token(config) do
    # TODO write a simple behaviour and provider implementation for this and inject with Application.get_env so this can be testable
    file_reader = Application.get_env(:ex_aws, :file_reader)
    token_file_path = Map.get(config, :web_identity_token_file)

    file_reader.read_file_contents(token_file_path)
  end

  @doc """
  Defines which sts endpoint to use, based on use of regional endpoints
  """
  def sts_endpoint(%{use_sts_regional_endpoints: true, region: region}),
    do: "#{ExAws.Config.Defaults.host(:sts, region)}"

  def sts_endpoint(_), do: "sts.amazonaws.com"
end
