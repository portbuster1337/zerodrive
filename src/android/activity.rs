use jni::JNIEnv;
use jni::objects::{JClass, JString};
use jni::sys::{jboolean, jstring};

fn to_jstring(env: &mut JNIEnv, s: &str) -> jstring {
    match env.new_string(s) {
        Ok(jstr) => jstr.into_inner(),
        Err(_) => std::ptr::null_mut(),
    }
}

fn rust_str(env: &mut JNIEnv, s: &JString) -> String {
    env.get_string(s.clone())
        .map(|jstr| jstr.to_str().unwrap_or("").to_string())
        .unwrap_or_default()
}

fn with_panic_boundary<F>(env: &mut JNIEnv, f: F) -> jstring
where F: FnOnce(&mut JNIEnv) -> jstring + std::panic::UnwindSafe
{
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(env))) {
        Ok(s) => s,
        Err(_) => to_jstring(env, &serde_json::json!({"error": "internal panic"}).to_string()),
    }
}

fn bool_to_jboolean(b: bool) -> jboolean {
    if b { 1 } else { 0 }
}

fn with_panic_boundary_bool<F>(env: &mut JNIEnv, f: F) -> jboolean
where F: FnOnce(&mut JNIEnv) -> jboolean + std::panic::UnwindSafe
{
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(env))) {
        Ok(b) => b,
        Err(_) => 0,
    }
}

#[no_mangle]
pub extern "system" fn Java_com_zerodrive_app_MainActivity_nativeInit(
    _env: JNIEnv,
    _class: JClass,
) {
    android_logger::init_once(
        android_logger::Config::default().with_max_level(log::LevelFilter::Debug).with_tag("ZeroDrive"),
    );
    log::info!("ZeroDrive native init");
    crate::android::runtime::init();
}

#[no_mangle]
pub extern "system" fn Java_com_zerodrive_app_MainActivity_nativeStartDaemon(
    mut env: JNIEnv,
    _class: JClass,
    mnemonic: JString,
) -> jstring {
    with_panic_boundary(&mut env, |env| {
        let s = rust_str(env, &mnemonic);
        to_jstring(env, &crate::android::runtime::start_daemon(&s))
    })
}

#[no_mangle]
pub extern "system" fn Java_com_zerodrive_app_MainActivity_nativeListDrives(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    with_panic_boundary(&mut env, |env| {
        to_jstring(env, &crate::android::runtime::list_drives())
    })
}

#[no_mangle]
pub extern "system" fn Java_com_zerodrive_app_MainActivity_nativeListFiles(
    mut env: JNIEnv,
    _class: JClass,
    drive: JString,
) -> jstring {
    with_panic_boundary(&mut env, |env| {
        let s = rust_str(env, &drive);
        to_jstring(env, &crate::android::runtime::list_files(&s))
    })
}

#[no_mangle]
pub extern "system" fn Java_com_zerodrive_app_MainActivity_nativeCreateDrive(
    mut env: JNIEnv,
    _class: JClass,
    name: JString,
) -> jboolean {
    with_panic_boundary_bool(&mut env, |env| {
        let s = rust_str(env, &name);
        bool_to_jboolean(crate::android::runtime::create_drive(&s))
    })
}

#[no_mangle]
pub extern "system" fn Java_com_zerodrive_app_MainActivity_nativeDeleteDrive(
    mut env: JNIEnv,
    _class: JClass,
    name: JString,
) -> jboolean {
    with_panic_boundary_bool(&mut env, |env| {
        let s = rust_str(env, &name);
        bool_to_jboolean(crate::android::runtime::delete_drive(&s))
    })
}

#[no_mangle]
pub extern "system" fn Java_com_zerodrive_app_MainActivity_nativeDeleteFile(
    mut env: JNIEnv,
    _class: JClass,
    drive: JString,
    file: JString,
) -> jboolean {
    with_panic_boundary_bool(&mut env, |env| {
        let d = rust_str(env, &drive);
        let f = rust_str(env, &file);
        bool_to_jboolean(crate::android::runtime::delete_file(&d, &f))
    })
}

#[no_mangle]
pub extern "system" fn Java_com_zerodrive_app_MainActivity_nativeUploadFile(
    mut env: JNIEnv,
    _class: JClass,
    drive: JString,
    file_path: JString,
) -> jstring {
    with_panic_boundary(&mut env, |env| {
        let d = rust_str(env, &drive);
        let p = rust_str(env, &file_path);
        to_jstring(env, &crate::android::runtime::upload_file(&d, &p))
    })
}

#[no_mangle]
pub extern "system" fn Java_com_zerodrive_app_MainActivity_nativeDownloadFile(
    mut env: JNIEnv,
    _class: JClass,
    drive: JString,
    file_name: JString,
    dest_path: JString,
) -> jstring {
    with_panic_boundary(&mut env, |env| {
        let d = rust_str(env, &drive);
        let f = rust_str(env, &file_name);
        let p = rust_str(env, &dest_path);
        to_jstring(env, &crate::android::runtime::download_file(&d, &f, &p))
    })
}
