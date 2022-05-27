// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.google.firebase.appdistribution.impl;

import static com.google.firebase.appdistribution.impl.TaskUtils.runAsyncInTask;

import android.content.Context;
import android.content.pm.PackageManager;
import androidx.annotation.NonNull;
import androidx.annotation.VisibleForTesting;
import com.google.android.gms.common.util.AndroidUtilsLight;
import com.google.android.gms.common.util.Hex;
import com.google.android.gms.tasks.Task;
import com.google.android.gms.tasks.Tasks;
import com.google.firebase.FirebaseApp;
import com.google.firebase.appdistribution.BinaryType;
import com.google.firebase.appdistribution.FirebaseAppDistributionException;
import com.google.firebase.appdistribution.FirebaseAppDistributionException.Status;
import com.google.firebase.inject.Provider;
import com.google.firebase.installations.FirebaseInstallationsApi;
import com.google.firebase.installations.InstallationTokenResult;
import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.zip.GZIPOutputStream;
import javax.net.ssl.HttpsURLConnection;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

class FirebaseAppDistributionTesterApiClient {

  /** A potentially long-running job that requires a FID and a FIS auth token */
  private interface FidDependentJob<TResult> {
    TResult run(String fid, String token) throws FirebaseAppDistributionException;
  }

  private static final String APP_TESTERS_HOST = "firebaseapptesters.googleapis.com";
  private static final String FIND_RELEASE_APK_HASH_PARAM = "apkHash";
  private static final String FIND_RELEASE_IAS_ARTIFACT_ID_PARAM = "iasArtifactId";
  private static final String REQUEST_METHOD_GET = "GET";
  private static final String REQUEST_METHOD_POST = "POST";
  private static final String CONTENT_TYPE_HEADER_KEY = "Content-Type";
  private static final String JSON_CONTENT_TYPE = "application/json";
  private static final String CONTENT_ENCODING_HEADER_KEY = "Content-Encoding";
  private static final String GZIP_CONTENT_ENCODING = "gzip";
  private static final String API_KEY_HEADER = "x-goog-api-key";
  private static final String INSTALLATION_AUTH_HEADER = "X-Goog-Firebase-Installations-Auth";
  private static final String X_ANDROID_PACKAGE_HEADER_KEY = "X-Android-Package";
  private static final String X_ANDROID_CERT_HEADER_KEY = "X-Android-Cert";
  // Format of "X-Client-Version": "{ClientId}/{ClientVersion}"
  private static final String X_CLIENT_VERSION_HEADER_KEY = "X-Client-Version";

  private static final String BUILD_VERSION_JSON_KEY = "buildVersion";
  private static final String DISPLAY_VERSION_JSON_KEY = "displayVersion";
  private static final String RELEASE_NOTES_JSON_KEY = "releaseNotes";
  private static final String BINARY_TYPE_JSON_KEY = "binaryType";
  private static final String CODE_HASH_KEY = "codeHash";
  private static final String APK_HASH_KEY = "apkHash";
  private static final String IAS_ARTIFACT_ID_KEY = "iasArtifactId";
  private static final String DOWNLOAD_URL_KEY = "downloadUrl";

  private static final String TAG = "TesterApiClient:";
  private static final int DEFAULT_BUFFER_SIZE = 8192;

  private final FirebaseApp firebaseApp;
  private final Provider<FirebaseInstallationsApi> firebaseInstallationsApiProvider;
  private final HttpsUrlConnectionFactory httpsUrlConnectionFactory;
  private final Executor taskExecutor;

  FirebaseAppDistributionTesterApiClient(
      @NonNull FirebaseApp firebaseApp,
      @NonNull Provider<FirebaseInstallationsApi> firebaseInstallationsApiProvider) {
    this(
        Executors.newSingleThreadExecutor(),
        firebaseApp,
        firebaseInstallationsApiProvider,
        new HttpsUrlConnectionFactory());
  }

  @VisibleForTesting
  FirebaseAppDistributionTesterApiClient(
      @NonNull Executor taskExecutor,
      @NonNull FirebaseApp firebaseApp,
      @NonNull Provider<FirebaseInstallationsApi> firebaseInstallationsApiProvider,
      @NonNull HttpsUrlConnectionFactory httpsUrlConnectionFactory) {
    this.taskExecutor = taskExecutor;
    this.firebaseApp = firebaseApp;
    this.firebaseInstallationsApiProvider = firebaseInstallationsApiProvider;
    this.httpsUrlConnectionFactory = httpsUrlConnectionFactory;
  }

  /**
   * Fetches and returns a {@link Task} that will complete with the latest release for the app that
   * the tester has access to, or {@code null} if the tester doesn't have access to any releases.
   */
  @NonNull
  Task<AppDistributionReleaseInternal> fetchNewRelease() {
    return runWithFidAndToken(
        (fid, token) -> {
          String path =
              String.format(
                  "v1alpha/devices/-/testerApps/%s/installations/%s/releases",
                  firebaseApp.getOptions().getApplicationId(), fid);
          String responseBody = makeGetRequest(path, token);
          return parseNewRelease(responseBody);
        });
  }

  /**
   * Fetches and returns the name of the installed release given the hash of the installed APK, or
   * null if it could not be found.
   */
  @NonNull
  Task<String> findReleaseUsingApkHash(String apkHash) {
    return runWithFidAndToken(
        (fid, token) -> findRelease(fid, token, FIND_RELEASE_APK_HASH_PARAM, apkHash));
  }

  /**
   * Fetches and returns the name of the installed release given the IAS artifact ID of the
   * installed app bundle, or null if it could not be found.
   */
  @NonNull
  Task<String> findReleaseUsingIasArtifactId(String iasArtifactId) {
    return runWithFidAndToken(
        (fid, token) -> findRelease(fid, token, FIND_RELEASE_IAS_ARTIFACT_ID_PARAM, iasArtifactId));
  }

  private String findRelease(String fid, String token, String binaryIdParam, String binaryIdValue)
      throws FirebaseAppDistributionException {
    String path =
        String.format(
            "v1alpha/projects/%s/installations/%s/releases:find?%s=%s",
            firebaseApp.getOptions().getGcmSenderId(), // Project number
            fid,
            binaryIdParam,
            binaryIdValue);
    String responseBody = makeGetRequest(path, token);
    return parseJsonFieldFromResponse(responseBody, "release");
  }

  /** Creates a new feedback from the given text, and returns the feedback name. */
  @NonNull
  Task<String> createFeedback(String testerReleaseName, String feedbackText) {
    return runWithFidAndToken(
        (unused, token) -> {
          LogWrapper.getInstance().i("Creating feedback for release: " + testerReleaseName);
          String path = String.format("v1alpha/%s/feedback", testerReleaseName);
          String requestBody = buildCreateFeedbackBody(feedbackText).toString();
          String responseBody = makePostRequest(path, token, requestBody);
          return parseJsonFieldFromResponse(responseBody, "name");
        });
  }

  /** Commits the feedback with the given name. */
  @NonNull
  Task<Void> commitFeedback(String feedbackName) {
    return runWithFidAndToken(
        (unused, token) -> {
          LogWrapper.getInstance().i("Committing feedback: " + feedbackName);
          String path = "v1alpha/" + feedbackName + ":commit";
          makePostRequest(path, token, /* requestBody= */ "");
          return null;
        });
  }

  private static JSONObject buildCreateFeedbackBody(String feedbackText)
      throws FirebaseAppDistributionException {
    JSONObject feedbackJsonObject = new JSONObject();
    try {
      feedbackJsonObject.put("text", feedbackText);
    } catch (JSONException e) {
      throw new FirebaseAppDistributionException(
          ErrorMessages.JSON_SERIALIZATION_ERROR, Status.UNKNOWN, e);
    }
    return feedbackJsonObject;
  }

  private String readResponse(HttpsURLConnection connection)
      throws FirebaseAppDistributionException, IOException {
    int responseCode = connection.getResponseCode();
    String responseBody = readResponseBody(connection);
    LogWrapper.getInstance().v(String.format("Response (%d): %s", responseCode, responseBody));
    if (!isResponseSuccess(responseCode)) {
      throw getExceptionForHttpResponse(responseCode);
    }
    return responseBody;
  }

  private String makeGetRequest(String path, String token) throws FirebaseAppDistributionException {
    String url = String.format("https://%s/%s", APP_TESTERS_HOST, path);
    HttpsURLConnection connection = null;
    try {
      connection = openHttpsUrlConnection(url, token);
      return readResponse(connection);
    } catch (IOException e) {
      throw new FirebaseAppDistributionException(
          ErrorMessages.NETWORK_ERROR, Status.NETWORK_FAILURE, e);
    } finally {
      if (connection != null) {
        connection.disconnect();
      }
    }
  }

  private String makePostRequest(String path, String token, String requestBody)
      throws FirebaseAppDistributionException {
    String url = String.format("https://%s/%s", APP_TESTERS_HOST, path);
    HttpsURLConnection connection = null;
    try {
      connection = openHttpsUrlConnection(url, token);
      connection.setDoOutput(true);
      connection.setRequestMethod(REQUEST_METHOD_POST);
      connection.addRequestProperty(CONTENT_TYPE_HEADER_KEY, JSON_CONTENT_TYPE);
      connection.addRequestProperty(CONTENT_ENCODING_HEADER_KEY, GZIP_CONTENT_ENCODING);
      connection.getOutputStream();
      GZIPOutputStream gzipOutputStream = new GZIPOutputStream(connection.getOutputStream());
      try {
        gzipOutputStream.write(requestBody.getBytes("UTF-8"));
      } catch (IOException e) {
        throw new FirebaseAppDistributionException(
            "Error compressing network request body", Status.UNKNOWN, e);
      } finally {
        gzipOutputStream.close();
      }
      return readResponse(connection);
    } catch (IOException e) {
      throw new FirebaseAppDistributionException(
          ErrorMessages.NETWORK_ERROR, Status.NETWORK_FAILURE, e);
    } finally {
      if (connection != null) {
        connection.disconnect();
      }
    }
  }

  private String readResponseBody(HttpsURLConnection connection) throws IOException {
    boolean isSuccess = isResponseSuccess(connection.getResponseCode());
    try (InputStream inputStream =
        isSuccess ? connection.getInputStream() : connection.getErrorStream()) {
      if (inputStream == null && !isSuccess) {
        // If the server returns a response with an error code and no response body, getErrorStream
        // returns null. We return an empty string to reflect the empty body.
        return "";
      }
      return convertInputStreamToString(new BufferedInputStream(inputStream));
    }
  }

  private static boolean isResponseSuccess(int responseCode) {
    return responseCode >= 200 && responseCode < 300;
  }

  private AppDistributionReleaseInternal parseNewRelease(String responseBody)
      throws FirebaseAppDistributionException {
    try {
      JSONObject responseJson = new JSONObject(responseBody);
      if (!responseJson.has("releases")) {
        return null;
      }
      JSONArray releasesJson = responseJson.getJSONArray("releases");
      if (releasesJson.length() == 0) {
        return null;
      }
      JSONObject newReleaseJson = releasesJson.getJSONObject(0);
      final String displayVersion = newReleaseJson.getString(DISPLAY_VERSION_JSON_KEY);
      final String buildVersion = newReleaseJson.getString(BUILD_VERSION_JSON_KEY);
      String releaseNotes = tryGetValue(newReleaseJson, RELEASE_NOTES_JSON_KEY);
      String codeHash = tryGetValue(newReleaseJson, CODE_HASH_KEY);
      String apkHash = tryGetValue(newReleaseJson, APK_HASH_KEY);
      String iasArtifactId = tryGetValue(newReleaseJson, IAS_ARTIFACT_ID_KEY);
      String downloadUrl = tryGetValue(newReleaseJson, DOWNLOAD_URL_KEY);

      final BinaryType binaryType =
          newReleaseJson.getString(BINARY_TYPE_JSON_KEY).equals("APK")
              ? BinaryType.APK
              : BinaryType.AAB;

      AppDistributionReleaseInternal newRelease =
          AppDistributionReleaseInternal.builder()
              .setDisplayVersion(displayVersion)
              .setBuildVersion(buildVersion)
              .setReleaseNotes(releaseNotes)
              .setBinaryType(binaryType)
              .setIasArtifactId(iasArtifactId)
              .setCodeHash(codeHash)
              .setApkHash(apkHash)
              .setDownloadUrl(downloadUrl)
              .build();

      LogWrapper.getInstance().v("Zip hash for the new release " + newRelease.getApkHash());
      return newRelease;
    } catch (JSONException e) {
      LogWrapper.getInstance().e(TAG + "Error parsing the new release.", e);
      throw new FirebaseAppDistributionException(
          ErrorMessages.JSON_PARSING_ERROR, Status.UNKNOWN, e);
    }
  }

  private String parseJsonFieldFromResponse(String responseBody, String fieldName)
      throws FirebaseAppDistributionException {
    JSONObject responseJson;
    try {
      responseJson = new JSONObject(responseBody);
    } catch (JSONException e) {
      LogWrapper.getInstance().e(TAG + "Error parsing the response.", e);
      throw new FirebaseAppDistributionException(
          ErrorMessages.JSON_PARSING_ERROR, Status.UNKNOWN, e);
    }

    try {
      return responseJson.getString(fieldName);
    } catch (JSONException e) {
      LogWrapper.getInstance()
          .e(TAG + String.format("Field '%s' missing from response", fieldName), e);
      throw new FirebaseAppDistributionException(
          ErrorMessages.JSON_PARSING_ERROR, Status.UNKNOWN, e);
    }
  }

  private FirebaseAppDistributionException getExceptionForHttpResponse(int responseCode) {
    switch (responseCode) {
      case 400:
        return new FirebaseAppDistributionException("Bad request", Status.UNKNOWN);
      case 401:
        return new FirebaseAppDistributionException(
            ErrorMessages.AUTHENTICATION_ERROR, Status.AUTHENTICATION_FAILURE);
      case 403:
        return new FirebaseAppDistributionException(
            ErrorMessages.AUTHORIZATION_ERROR, Status.AUTHENTICATION_FAILURE);
      case 404:
        // TODO(lkellogg): Need to provide more tailored error messages for 404s
        return new FirebaseAppDistributionException(ErrorMessages.NOT_FOUND_ERROR, Status.UNKNOWN);
      case 408:
      case 504:
        return new FirebaseAppDistributionException(
            ErrorMessages.TIMEOUT_ERROR, Status.NETWORK_FAILURE);
      default:
        return new FirebaseAppDistributionException(
            "Received error status: " + responseCode, Status.UNKNOWN);
    }
  }

  private String tryGetValue(JSONObject jsonObject, String key) {
    try {
      return jsonObject.getString(key);
    } catch (JSONException e) {
      return "";
    }
  }

  private HttpsURLConnection openHttpsUrlConnection(String url, String authToken)
      throws IOException {
    LogWrapper.getInstance().v("Opening connection to " + url);
    Context context = firebaseApp.getApplicationContext();
    HttpsURLConnection httpsURLConnection;
    httpsURLConnection = httpsUrlConnectionFactory.openConnection(url);
    httpsURLConnection.setRequestMethod(REQUEST_METHOD_GET);
    httpsURLConnection.setRequestProperty(API_KEY_HEADER, firebaseApp.getOptions().getApiKey());
    httpsURLConnection.setRequestProperty(INSTALLATION_AUTH_HEADER, authToken);
    httpsURLConnection.addRequestProperty(X_ANDROID_PACKAGE_HEADER_KEY, context.getPackageName());
    httpsURLConnection.addRequestProperty(
        X_ANDROID_CERT_HEADER_KEY, getFingerprintHashForPackage());
    httpsURLConnection.addRequestProperty(
        X_CLIENT_VERSION_HEADER_KEY, String.format("android-sdk/%s", BuildConfig.VERSION_NAME));
    return httpsURLConnection;
  }

  private static String convertInputStreamToString(InputStream is) throws IOException {
    ByteArrayOutputStream result = new ByteArrayOutputStream();
    byte[] buffer = new byte[DEFAULT_BUFFER_SIZE];
    int length;
    while ((length = is.read(buffer)) != -1) {
      result.write(buffer, 0, length);
    }
    return result.toString();
  }

  /** Gets the Android package's SHA-1 fingerprint. */
  private String getFingerprintHashForPackage() {
    Context context = firebaseApp.getApplicationContext();
    byte[] hash;

    try {
      hash = AndroidUtilsLight.getPackageCertificateHashBytes(context, context.getPackageName());

      if (hash == null) {
        LogWrapper.getInstance()
            .e(
                TAG
                    + "Could not get fingerprint hash for X-Android-Cert header. Package is not signed: "
                    + context.getPackageName());
        return null;
      } else {
        return Hex.bytesToStringUppercase(hash, /* zeroTerminated= */ false);
      }
    } catch (PackageManager.NameNotFoundException e) {
      LogWrapper.getInstance()
          .e(
              TAG
                  + "Could not get fingerprint hash for X-Android-Cert header. No such package: "
                  + context.getPackageName(),
              e);
      return null;
    }
  }

  /**
   * Asynchronously runs a potentially long-running job that depends on a FID and a FIS auth token.
   */
  private <TResult> Task<TResult> runWithFidAndToken(FidDependentJob<TResult> job) {
    Task<String> installationIdTask = firebaseInstallationsApiProvider.get().getId();
    // forceRefresh is false to get locally cached token if available
    Task<InstallationTokenResult> installationAuthTokenTask =
        firebaseInstallationsApiProvider.get().getToken(/* forceRefresh= */ false);

    return Tasks.whenAllSuccess(installationIdTask, installationAuthTokenTask)
        .continueWithTask(TaskUtils::handleTaskFailure)
        .onSuccessTask(
            resultsList -> {
              // Tasks.whenAllSuccess combines task results into a list
              if (resultsList.size() != 2) {
                throw new FirebaseAppDistributionException(
                    "Expected 2 task results, got " + resultsList.size(), Status.UNKNOWN);
              }
              String fid = (String) resultsList.get(0);
              InstallationTokenResult tokenResult = (InstallationTokenResult) resultsList.get(1);
              return runAsyncInTask(taskExecutor, () -> job.run(fid, tokenResult.getToken()));
            });
  }
}
