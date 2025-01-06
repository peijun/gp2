----------------------------------------------------
-- グローバル変数
----------------------------------------------------
obs           = obslua
source_name   = ""  -- 選択中のメディアソース名を格納

-- 再生回数を数える変数
local play_count     = 0   -- 現在までに再生した回数
local max_play_count = 6   -- 最終的に配信停止したい再生回数

----------------------------------------------------
-- スクリプトの基本情報
----------------------------------------------------
function script_description()
    return [[
メディアソースが指定回数（デフォルト 6回）再生終了したら自動的に配信を停止するサンプルスクリプト。

【機能概要】
1) 配信が開始されたとき:
   - 再生回数カウンタを0に初期化
   - 指定されたメディアソースを最初から再生し直す
   - 500msごとにメディアソースの再生状態をチェックする

2) メディアソースが END (または STOP) 状態になったとき:
   - 再生回数をカウント
   - 指定回数 (デフォルト 6回) に満たない場合は自動で再生し直す
   - 指定回数に到達したら配信停止

【使い方】
1. 「スクリプト」タブで本Luaファイルを読み込み
2. 「プロパティ」で監視したいメディアソースを選択
3. 通常通りに「配信開始」ボタンを押す
]]
end

----------------------------------------------------
-- スクリプトのプロパティ定義
----------------------------------------------------
function script_properties()
    local props = obs.obs_properties_create()

    -- 「メディアソース」選択リストを追加
    local p = obs.obs_properties_add_list(
        props,
        "source",
        "メディアソースを選択",
        obs.OBS_COMBO_TYPE_LIST,
        obs.OBS_COMBO_FORMAT_STRING
    )

    -- シーン内のソースを列挙し、ffmpeg_source / vlc_source のみ候補に追加
    local sources = obs.obs_enum_sources()
    if sources ~= nil then
        for _, source in ipairs(sources) do
            local source_id = obs.obs_source_get_id(source)
            if source_id == "ffmpeg_source" or source_id == "vlc_source" then
                local name = obs.obs_source_get_name(source)
                obs.obs_property_list_add_string(p, name, name)
            end
        end
        obs.source_list_release(sources)
    end

    return props
end

----------------------------------------------------
-- スクリプトの更新イベント
----------------------------------------------------
function script_update(settings)
    -- 「メディアソースを選択」で選ばれた名前を取得
    source_name = obs.obs_data_get_string(settings, "source")
end

----------------------------------------------------
-- スクリプト読み込み時の初期化
----------------------------------------------------
function script_load(settings)
    -- OBSのイベント（配信開始/停止など）をフックするコールバックを登録
    obs.obs_frontend_add_event_callback(on_event)
end

----------------------------------------------------
-- OBSフロントエンドイベント時に呼ばれる関数
----------------------------------------------------
function on_event(event)
    -- 配信が開始されたとき
    if event == obs.OBS_FRONTEND_EVENT_STREAMING_STARTED then
        -- カウンタをリセット
        play_count = 0

        -- メディアソースを再スタート
        restart_media_source()

        -- メディアソースの状態を定期チェック開始
        start_check_timer()

    -- 配信が停止したとき
    elseif event == obs.OBS_FRONTEND_EVENT_STREAMING_STOPPED then
        -- タイマーを解除
        stop_check_timer()
    end
end

----------------------------------------------------
-- メディアソースを最初から再生する関数
----------------------------------------------------
function restart_media_source()
    if not source_name or source_name == "" then
        return
    end
    local source = obs.obs_get_source_by_name(source_name)
    if source ~= nil then
        -- メディアソースの再生を一旦リセット
        obs.obs_source_media_restart(source)
        obs.obs_source_release(source)
    end
end

----------------------------------------------------
-- タイマーを起動し、定期的にメディアの状態を確認
----------------------------------------------------
function start_check_timer()
    -- 500ミリ秒ごとに check_media_state() を呼ぶ
    obs.timer_add(check_media_state, 500)
end

----------------------------------------------------
-- タイマーを停止
----------------------------------------------------
function stop_check_timer()
    obs.timer_remove(check_media_state)
end

----------------------------------------------------
-- メディアソースの状態を確認し、再生終了時の挙動を管理
----------------------------------------------------
function check_media_state()
    if not source_name or source_name == "" then
        return
    end
    local source = obs.obs_get_source_by_name(source_name)
    if source == nil then
        return
    end

    local state = obs.obs_source_media_get_state(source)
    obs.obs_source_release(source)

    -- 終了状態(ENDEDまたはSTOPPED) なら
    if state == obs.OBS_MEDIA_STATE_ENDED or state == obs.OBS_MEDIA_STATE_STOPPED then
        -- 再生回数を1回増加
        play_count = play_count + 1
        print("Media ended. play_count = " .. play_count)

        -- まだ指定回数に達していなければ再生し直す
        if play_count < max_play_count then
            restart_media_source()
        else
            -- 指定回数(6回)に到達したら配信停止
            obs.obs_frontend_streaming_stop()
        end
    end
end
